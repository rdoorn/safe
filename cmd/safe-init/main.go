// Package main is the entrypoint for the in-container PID 1 (safe-init).
//
// safe-init brings up the SAFE runtime in this order:
//  1. Remount /proc with hidepid=2 so non-firewall uids can't see other
//     users' processes.
//  2. Run safe-fw once to seed nftables.
//  3. Spawn safe-dns as user `firewall` (cap_net_admin via file caps).
//  4. Spawn safe-keyholder as user `keyholder`, pipe the LLM API key
//     received over the one-shot TCP bootstrap port into its stdin once.
//  5. Drop to user `agent`, set no_new_privs, exec the configured agent
//     with the agent's args.
//  6. Forward host signals to the agent and reap any zombies that
//     appear in PID 1's children.
//
// All steps after (1) only function on Linux; the package compiles on
// other platforms for ergonomics but main() refuses to run there.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/initd"
)

const (
	defaultFirewallUID     = 200
	defaultFirewallGID     = 200
	defaultKeyholderUID    = 201
	defaultAgentUID        = 1000
	defaultAgentGID        = 1000
	bootstrapPort          = "9099" // must match internal/dockerrun.BootstrapPort
	configPath             = "/etc/safe/config.yaml"
	safeFW                 = "/usr/sbin/safe-fw"
	safeDNS                = "/usr/sbin/safe-dns"
	safeKeyholder          = "/usr/sbin/safe-keyholder"
	agentClaudeDir         = "/home/agent/.claude"
	agentClaudeProjectsDir = "/home/agent/.claude/projects"
	agentCacheDir          = "/home/agent/.cache"
	goTmpDir               = "/home/agent/.cache/gotmp"
	keyPipeTimeout         = 10 * time.Second
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: safe-init <agent-name> [agent-args...]")
		os.Exit(2)
	}

	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "safe-init: requires Linux (refusing to run on", runtime.GOOS+")")
		os.Exit(1)
	}

	agentName, agentArgs := args[0], args[1:]
	if err := run(agentName, agentArgs); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init:", err)
		os.Exit(1)
	}
}

// keyholderEnabled gates the auth bootstrap + safe-keyholder spawn.
// The matching switch on the host side is `KeyholderEnabled` in
// internal/dockerrun/constants.go; the two MUST be kept in lockstep.
const keyholderEnabled = true

func run(agentName string, agentArgs []string) error { //nolint:gocyclo // linear init pipeline with best-effort skip branches; splitting hurts readability
	logStage := func(stage int, msg string) {
		fmt.Fprintf(os.Stderr, "safe-init: stage=%d %s\n", stage, msg)
	}

	// Bootstrap secret MUST be received first — even before hidepid and
	// the chown block. Docker exposes the host port mapping as soon as
	// the container starts; if the host CLI's PipeKey connects and
	// writes before our listener exists, docker-proxy accepts the bytes
	// and drops them silently. That race was visible as a ~1-in-10
	// "accept on :9099: i/o timeout" failure when we did chowns first.
	var secret []byte
	authMode := ""
	if keyholderEnabled {
		logStage(0, "read bootstrap secret (FIRST; before any other work)")
		var ferr error
		authMode, ferr = resolveAuthMode(agentName)
		if ferr != nil {
			return fmt.Errorf("determine auth mode: %w", ferr)
		}
		s, rerr := readSecretFromTCP(bootstrapPort, keyPipeTimeout)
		if rerr != nil {
			return fmt.Errorf("read auth secret: %w", rerr)
		}
		secret = s
	}

	logStage(1, "remount /proc hidepid=2 (best-effort)")
	if err := initd.RemountProcHidepid(defaultFirewallGID); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: hidepid remount skipped:", err)
		fmt.Fprintln(os.Stderr, "safe-init: add --cap-add SYS_ADMIN to docker run to enable PID hiding")
	}

	// Docker auto-creates /home/agent/.claude as root:root mode 755 when
	// it resolves the bind-mount parent path for the customization mounts
	// (skills, commands, CLAUDE.md, ...). The agent uid (1000) then can't
	// write its own .credentials.json or session state into its own home.
	// Chown the dir over to agent before the agent runs. The agent ownership
	// of /home/agent itself is set by the docker --tmpfs uid=1000,gid=1000
	// option in BuildArgv; only the subdir needs fixing here.
	if err := os.Chown(agentClaudeDir, int(defaultAgentUID), int(defaultAgentGID)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "safe-init: chown", agentClaudeDir, "skipped:", err)
	}
	// Persistent build/tool cache is bind-mounted as a docker named
	// volume; volumes are created root-owned by default. Agent can't
	// write to it without this chown. Without it, Go's GOCACHE,
	// GOMODCACHE, npm cache, pip cache, etc. all fail.
	if err := os.Chown(agentCacheDir, int(defaultAgentUID), int(defaultAgentGID)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "safe-init: chown", agentCacheDir, "skipped:", err)
	}
	// claude session jsonl files live here. Persistent docker volume
	// mounted by SAFE; default root-owned, agent (uid 1000) needs to
	// write claude's session state for /resume to work across runs.
	if err := os.Chown(agentClaudeProjectsDir, int(defaultAgentUID), int(defaultAgentGID)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "safe-init: chown", agentClaudeProjectsDir, "skipped:", err)
	}
	// Pre-create $GOTMPDIR so Go's test linker (which execs binaries
	// from $WORK) has an exec-allowed scratch dir; /tmp is noexec to
	// block RCE-payload exec, but go test needs to exec freshly built
	// test binaries somewhere.
	if err := os.MkdirAll(goTmpDir, 0o755); err != nil { //nolint:gosec
		fmt.Fprintln(os.Stderr, "safe-init: mkdir", goTmpDir, "skipped:", err)
	} else if err := os.Chown(goTmpDir, int(defaultAgentUID), int(defaultAgentGID)); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: chown", goTmpDir, "skipped:", err)
	}

	// Stage in the host's .claude.json (per-user state with theme/trust
	// prefs) to the agent's writable home. Host wrote it next to
	// config.yaml under /etc/safe/. If absent (state mount disabled),
	// silently skip.
	if err := stageClaudeState(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: stage claude-state.json skipped:", err)
	}
	if err := stageClaudeSettings(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: stage claude-settings.json skipped:", err)
	}

	logStage(3, "run safe-fw to seed nftables")
	if err := runSafeFW(); err != nil {
		return fmt.Errorf("safe-fw seed: %w", err)
	}

	logStage(4, "spawn safe-dns as uid 200")
	dnsCmd, err := startUserProcess(safeDNS, []string{"--config", configPath},
		defaultFirewallUID, defaultFirewallGID, nil)
	if err != nil {
		return fmt.Errorf("start safe-dns: %w", err)
	}

	var keyholderCmd *exec.Cmd
	if keyholderEnabled {
		logStage(5, "spawn safe-keyholder as uid 201")
		keyholderCmd, err = startUserProcess(safeKeyholder,
			[]string{"--config", configPath, "--agent", agentName, "--mode", authMode},
			defaultKeyholderUID, defaultKeyholderUID, secret)
		if err != nil {
			return fmt.Errorf("start safe-keyholder: %w", err)
		}
	} else {
		logStage(5, fmt.Sprintf("SKIPPED safe-keyholder (mode=%s)", authMode))
	}

	// Tighten the bounding set BEFORE spawning the agent so anything the
	// agent execs can never gain these caps via file caps or setuid bits.
	// safe-dns / safe-keyholder are already running and unaffected. See
	// hardenAgentSubtree() doc for details.
	if err := hardenAgentSubtree(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: agent-subtree hardening skipped:", err)
	}

	// Drop the agent under us. We do NOT use initd.DropPrivileges on
	// ourselves because we still need root to reap zombies; instead the
	// agent runs in its own credential via SysProcAttr.
	agentBin := resolveAgentPath(agentName)
	logStage(6, fmt.Sprintf("spawn agent: bin=%s args=%v uid=%d", agentBin, agentArgs, defaultAgentUID))
	agentCmd, err := startAgent(agentBin, agentArgs, defaultAgentUID, defaultAgentGID)
	if err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	logStage(7, fmt.Sprintf("supervise (agent pid=%d, waiting for exit)", agentCmd.Process.Pid))
	return supervise(agentCmd, dnsCmd, keyholderCmd)
}

func runSafeFW() error {
	cmd := exec.Command(safeFW, "--config", configPath) //nolint:gosec // constants only
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startAgent spawns the foreground agent process as the given uid/gid,
// inheriting safe-init's stdin/stdout/stderr so the agent shares the
// docker-allocated TTY (interactive REPL) or pipes (non-interactive
// runs). Without this, the agent's stdin defaults to /dev/null and
// TTY-detecting agents like claude exit immediately as if they were
// being piped to.
//
// We deliberately do NOT set Setpgid here (unlike startUserProcess for
// daemons). The container's controlling-TTY foreground process group is
// safe-init's group (pgrp 1). If the agent were in its own process
// group, any read of the TTY (tcgetattr, TIOCGWINSZ, stdin read) would
// fault with SIGTTIN and the kernel would stop the agent (state T).
// Inheriting pgrp 1 makes the agent the foreground group of the PTY.
//
// We also override HOME/USER/LOGNAME because syscall.Credential only
// sets the uid/gid — the env is inherited from safe-init (root), so
// without this the child sees HOME=/root and tries to read/write its
// config under /root (which is on the read-only rootfs).
func startAgent(bin string, args []string, uid, gid uint32) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...) //nolint:gosec // bin/args derived from validated config + PATH lookup
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = agentEnv(os.Environ())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	return cmd, nil
}

// agentEnv returns parent's env with HOME/USER/LOGNAME replaced to
// point at the agent uid's home/account inside the image.
func agentEnv(parent []string) []string {
	filtered := parent[:0:0]
	for _, e := range parent {
		switch {
		case strings.HasPrefix(e, "HOME="),
			strings.HasPrefix(e, "USER="),
			strings.HasPrefix(e, "LOGNAME="):
			continue
		default:
			filtered = append(filtered, e)
		}
	}
	return append(filtered,
		"HOME=/home/agent",
		"USER=agent",
		"LOGNAME=agent",
		// /tmp is noexec (anti-RCE); GOTMPDIR points at the persistent
		// cache volume which IS exec-allowed so `go test` can run its
		// freshly compiled test binaries.
		"GOTMPDIR="+goTmpDir,
	)
}

// startUserProcess spawns a background daemon as the given uid/gid, with
// optional stdin bytes (used to one-shot pipe the keyholder secret).
// The child inherits stdout/stderr but NOT stdin (it gets /dev/null) —
// daemons here are TCP listeners, none of them read keyboard input.
func startUserProcess(bin string, args []string, uid, gid uint32, stdin []byte) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...) //nolint:gosec // bin/args derived from constants and validated config
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		Setpgid:    true,
	}
	// NB: no-new-privs is enforced container-wide via the docker run
	// `--security-opt no-new-privileges` flag, so we don't need a
	// per-exec prctl here.
	if stdin != nil {
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("stdin pipe: %w", err)
		}
		go func() {
			defer func() { _ = stdinPipe.Close() }()
			_, _ = stdinPipe.Write(stdin)
		}()
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	return cmd, nil
}

// stageClaudeSettings is the settings.json sibling of stageClaudeState
// — see that function's doc comment.
func stageClaudeSettings() error {
	return stageAsAgent("/etc/safe/claude-settings.json", "/home/agent/.claude/settings.json")
}

// stageAsAgent copies src to dst by forking /bin/sh as the agent uid.
// We don't write directly because safe-init (uid 0) doesn't have
// CAP_DAC_OVERRIDE and /home/agent is owned by uid 1000.
func stageAsAgent(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", src, err)
	}
	cmd := exec.Command("/bin/sh", "-c", "umask 077 && cat "+src+" > "+dst) //nolint:gosec // src and dst are constants from callers
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: defaultAgentUID, Gid: defaultAgentGID, NoSetGroups: true},
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stage as agent uid: %w", err)
	}
	return nil
}

// stageClaudeState copies the host-staged claude-state.json (delivered
// inside the /etc/safe bind mount) into the agent's writable home at
// /home/agent/.claude.json with owner agent:agent and mode 0600. This
// is how SAFE seeds claude's per-user state (theme prefs, trust list,
// etc.) without giving the agent write access to the host file.
//
// The write is done by forking a /bin/sh as uid 1000 because safe-init
// (uid 0) doesn't have CAP_DAC_OVERRIDE — and /home/agent is mode 755
// owned by uid 1000, so uid 0 only has r-x on it. The agent uid IS the
// owner and can write freely; we let it do the write for us.
//
// A missing source is not an error — claude just starts fresh.
func stageClaudeState() error {
	return stageAsAgent("/etc/safe/claude-state.json", "/home/agent/.claude.json")
}

// resolveAuthMode reads the SAFE config and decides whether the agent
// uses a static API key or OAuth credentials.
func resolveAuthMode(agentName string) (string, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return "", err
	}
	a, ok := cfg.Agents[agentName]
	if !ok {
		return "", fmt.Errorf("agent %q not in config", agentName)
	}
	switch {
	case a.AuthCredentialsFile != "":
		return "oauth", nil
	case a.AuthEnv != "":
		return "apikey", nil
	default:
		return "", fmt.Errorf("agent %q has neither auth_env nor auth_credentials_file", agentName)
	}
}

// readSecretFromTCP waits up to timeout for the host to connect on the
// in-container TCP port and write the auth secret (API key line or
// credentials JSON blob). Reads until EOF so multi-line OAuth payloads
// work too. The listener binds 0.0.0.0 because the docker-proxy reaches
// us via the bridge interface, not loopback.
func readSecretFromTCP(port string, timeout time.Duration) ([]byte, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return nil, fmt.Errorf("listen tcp 0.0.0.0:%s: %w", port, err)
	}
	defer func() { _ = ln.Close() }()

	if t, ok := ln.(*net.TCPListener); ok {
		_ = t.SetDeadline(time.Now().Add(timeout))
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept on :%s: %w", port, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	const maxSecretBytes = 1 << 16 // 64 KiB — generous for OAuth JSON
	data, err := io.ReadAll(io.LimitReader(conn, maxSecretBytes))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return data, nil
}

// supervise waits for the agent to exit, forwards SIGINT/SIGTERM from
// PID 1 to the agent, and reaps the helper processes on exit.
func supervise(agent, dns, keyholder *exec.Cmd) error {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalEvents := make(chan initd.SignalEvent, 4)
	go initd.ForwardSignals(ctx, signalEvents, agent.Process.Pid, initd.KillSignaller{})
	go func() {
		for s := range sigCh {
			if sig, ok := s.(syscall.Signal); ok {
				signalEvents <- initd.SignalEvent{Sig: sig}
			}
		}
	}()

	err := agent.Wait()
	cancel()

	// Helpers no longer have a useful agent to serve; signal them to exit.
	for _, c := range []*exec.Cmd{dns, keyholder} {
		if c != nil && c.Process != nil {
			_ = c.Process.Signal(syscall.SIGTERM)
		}
	}
	// Drain any remaining zombies that aren't our direct children.
	for {
		var ws syscall.WaitStatus
		pid, werr := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || werr != nil {
			break
		}
	}
	return err
}

// resolveAgentPath maps the agent name to its in-container binary path.
// Looks up `name` on PATH so the image-build location is decoupled from
// safe-init: claude is installed via `npm install -g` which lands at
// /usr/local/bin/claude, other agents may be in /usr/bin or elsewhere.
// PATH lookup keeps safe-init agnostic.
func resolveAgentPath(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}
