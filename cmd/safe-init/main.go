// Package main is the entrypoint for the in-container PID 1 (safe-init).
//
// safe-init brings up the SAFE runtime in this order:
//  1. Remount /proc with hidepid=2 so non-firewall uids can't see other
//     users' processes.
//  2. Run safe-fw once to seed nftables.
//  3. Spawn safe-dns as user `firewall` (cap_net_admin via file caps).
//  4. Spawn safe-keyholder as user `keyholder`, pipe the LLM API key
//     from /run/safe/keyholder.sock into its stdin once.
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
	keyholderSocket     = "/run/safe/keyholder.sock"
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

func run(agentName string, agentArgs []string) error {
	if err := initd.RemountProcHidepid(defaultFirewallGID); err != nil {
		return fmt.Errorf("remount /proc: %w", err)
	}

	if err := runSafeFW(); err != nil {
		return fmt.Errorf("safe-fw seed: %w", err)
	}

	dnsCmd, err := startUserProcess(safeDNS, []string{"--config", configPath},
		defaultFirewallUID, defaultFirewallGID, nil)
	if err != nil {
		return fmt.Errorf("start safe-dns: %w", err)
	}

	authMode, err := resolveAuthMode(agentName)
	if err != nil {
		return fmt.Errorf("determine auth mode: %w", err)
	}

	secret, err := readSecretFromSocket(keyholderSocket, keyPipeTimeout)
	if err != nil {
		return fmt.Errorf("read auth secret: %w", err)
	}

	keyholderCmd, err := startUserProcess(safeKeyholder,
		[]string{"--config", configPath, "--agent", agentName, "--mode", authMode},
		defaultKeyholderUID, defaultKeyholderUID, secret)
	if err != nil {
		return fmt.Errorf("start safe-keyholder: %w", err)
	}

	// Drop the agent under us. We do NOT use initd.DropPrivileges on
	// ourselves because we still need root to reap zombies; instead the
	// agent runs in its own credential via SysProcAttr.
	agentCmd, err := startUserProcess(resolveAgentPath(agentName), agentArgs,
		defaultAgentUID, defaultAgentGID, nil)
	if err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	return supervise(agentCmd, dnsCmd, keyholderCmd)
}

func runSafeFW() error {
	cmd := exec.Command(safeFW, "--config", configPath) //nolint:gosec // constants only
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startUserProcess spawns argv as the given uid/gid, with optional stdin.
// stdin (when non-nil) is written and closed before the function returns
// so the child doesn't block on an open pipe.
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

// readSecretFromSocket waits up to timeout for the host to connect on
// socketPath and write the auth secret (API key line or credentials JSON
// blob). Reads until EOF so multi-line OAuth payloads work too.
func readSecretFromSocket(socketPath string, timeout time.Duration) ([]byte, error) {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socketPath, err)
	}
	defer func() { _ = ln.Close() }()
	_ = os.Chmod(socketPath, 0o600)

	if t, ok := ln.(*net.UnixListener); ok {
		_ = t.SetDeadline(time.Now().Add(timeout))
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept on %s: %w", socketPath, err)
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

// resolveAgentPath maps the agent name to its in-container binary.
// For v1 the registry is closed: only known names work, anything else
// is rejected before we get here by --doctor.
func resolveAgentPath(name string) string {
	switch name {
	case "claude":
		return "/usr/bin/claude"
	default:
		return "/usr/bin/" + name
	}
}
