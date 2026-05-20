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
	defaultFirewallUID  = 200
	defaultFirewallGID  = 200
	defaultKeyholderUID = 201
	defaultAgentUID     = 1000
	defaultAgentGID     = 1000
	bootstrapPort       = "9099" // must match internal/dockerrun.BootstrapPort
	configPath          = "/etc/safe/config.yaml"
	safeFW              = "/usr/sbin/safe-fw"
	safeDNS             = "/usr/sbin/safe-dns"
	safeKeyholder       = "/usr/sbin/safe-keyholder"
	keyPipeTimeout      = 10 * time.Second
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

func run(agentName string, agentArgs []string) error {
	logStage := func(stage int, msg string) {
		fmt.Fprintf(os.Stderr, "safe-init: stage=%d %s\n", stage, msg)
	}

	logStage(1, "remount /proc hidepid=2 (best-effort)")
	if err := initd.RemountProcHidepid(defaultFirewallGID); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: hidepid remount skipped:", err)
		fmt.Fprintln(os.Stderr, "safe-init: add --cap-add SYS_ADMIN to docker run to enable PID hiding")
	}

	// Bootstrap secret must come BEFORE safe-fw / safe-dns so the
	// in-container listener is up by the time docker reports the port
	// mapping to the host. Otherwise host's PipeKey wins the race against
	// the listener; docker-proxy eagerly accepts the host-side connection
	// and drops the bytes silently when the container side isn't ready.
	var secret []byte
	var authMode string
	if keyholderEnabled {
		logStage(2, "read bootstrap secret (listener first; firewall comes after)")
		var err error
		authMode, err = resolveAuthMode(agentName)
		if err != nil {
			return fmt.Errorf("determine auth mode: %w", err)
		}
		secret, err = readSecretFromTCP(bootstrapPort, keyPipeTimeout)
		if err != nil {
			return fmt.Errorf("read auth secret: %w", err)
		}
	} else {
		logStage(2, "SKIPPED bootstrap secret read (TEMP DEBUG, keyholderEnabled=false)")
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
		logStage(5, "SKIPPED safe-keyholder spawn (TEMP DEBUG)")
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
