package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/dockerrun"
	"gopkg.in/yaml.v3"
)

const (
	keyholderTimeout = 10 * time.Second
)

// runAgent is the path executed when the user runs `safe <agent> [args...]`.
// It loads/validates config, prepares the per-run state, and execs docker.
func runAgent(ctx context.Context, stdout, stderr io.Writer, xdgConfigDir, cwd, agentName string, agentArgs []string, shell bool) error { //nolint:gocyclo // linear pipeline with conditional stage logs; splitting hurts readability
	logStage := func(stage int, msg string) {
		_, _ = fmt.Fprintf(stderr, "safe: stage=%d %s\n", stage, msg)
	}

	logStage(1, "load+validate config")
	merged, agent, err := loadAgent(xdgConfigDir, cwd, agentName)
	if err != nil {
		return err
	}

	useKeyholder := dockerrun.KeyholderEnabled
	var secret []byte
	if useKeyholder {
		logStage(2, "resolve auth secret from "+authSecretSource(agent))
		secret, err = resolveAuthSecret(agent, shell)
		if err != nil {
			return err
		}
	} else {
		logStage(2, "SKIPPED keyholder bootstrap (KeyholderEnabled=false)")
	}

	runID := newRunID()
	runRoot := filepath.Join(cwd, ".safe", runID)
	logStage(3, "create run dir "+runRoot)
	if err := os.MkdirAll(runRoot, 0o755); err != nil { //nolint:gosec // 0o755 is intentional; container uids must traverse
		return fmt.Errorf("create run dir %s: %w", runRoot, err)
	}
	defer func() { _ = os.RemoveAll(runRoot) }()

	logStage(4, "serialize merged config + write into run dir")
	configYAML, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	configDir := filepath.Join(runRoot, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil { //nolint:gosec // 0o755 is intentional; container uids must traverse
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := dockerrun.WriteConfigDir(configDir, configYAML); err != nil {
		return err
	}

	if agent.Customization.State {
		if err := stageClaudeState(configDir); err != nil {
			_, _ = fmt.Fprintln(stderr, "safe: stage claude state:", err)
			// non-fatal — claude will just re-prompt for theme this run.
		}
	}

	logStage(5, "build docker argv")
	argv, err := buildDockerArgv(merged, agent, agentName, agentArgs, cwd, runID, configDir, shell)
	if err != nil {
		return err
	}

	logStage(6, fmt.Sprintf("docker run safe-%s (image=%s)", runID, agent.Image))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv constructed from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start docker: %w", err)
	}

	if useKeyholder && !shell && len(secret) > 0 {
		logStage(7, "pipeAuthSecret goroutine -> container")
		go pipeAuthSecret(ctx, stderr, "safe-"+runID, secret)
	}
	go forwardSignalsToDocker(cmd)

	logStage(8, "wait for docker to exit")
	return waitDocker(cmd)
}

// stageClaudeState copies the host's ~/.claude.json into the per-run
// config dir as claude-state.json so safe-init can in turn copy it into
// the agent's writable tmpfs home at /home/agent/.claude.json. The agent
// then has the host's theme/prefs/project history pre-populated AND can
// update it freely — but those updates only live for this container's
// lifetime (next session reads fresh from host).
//
// A missing host file is not an error: claude will just start fresh.
func stageClaudeState(configDir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home: %w", err)
	}
	src := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(src) //nolint:gosec // path is the user's own home
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", src, err)
	}
	dst := filepath.Join(configDir, "claude-state.json")
	if err := os.WriteFile(dst, data, 0o644); err != nil { //nolint:gosec // public to in-container uids; safe-init copies to agent home
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

// authSecretSource returns a short label for stage logs.
func authSecretSource(a config.Agent) string {
	if a.AuthCredentialsFile != "" {
		path := expandHome(a.AuthCredentialsFile)
		if _, err := os.Stat(path); os.IsNotExist(err) && runtime.GOOS == "darwin" {
			return fmt.Sprintf("macOS keychain (service %q; file %s missing)", claudeKeychainService, a.AuthCredentialsFile)
		}
		return "credentials file " + a.AuthCredentialsFile
	}
	if a.AuthEnv != "" {
		return "env var " + a.AuthEnv
	}
	return "<none>"
}

func loadAgent(xdgConfigDir, cwd, agentName string) (*config.Config, config.Agent, error) {
	configs, err := config.LoadAll(xdgConfigDir, cwd)
	if err != nil {
		return nil, config.Agent{}, fmt.Errorf("load configs: %w", err)
	}
	merged := config.MergeAll(configs)
	if err := config.Validate(merged, agentName); err != nil {
		return nil, config.Agent{}, fmt.Errorf("invalid config: %w", err)
	}
	a, ok := merged.Agents[agentName]
	if !ok {
		return nil, config.Agent{}, fmt.Errorf("agent %q not in registry", agentName)
	}
	return merged, a, nil
}

// resolveAuthSecret returns the bytes to pipe through the keyholder
// socket for the agent's chosen auth mode.
//
//   - API-key mode: returns "<key>\n" from the host env var.
//   - OAuth mode: returns the raw JSON contents of the credentials file
//     if present; if the file is absent on macOS, falls back to reading
//     the equivalent blob from the host's Keychain (where the desktop
//     claude binary now stores it by default — see "Claude Code-credentials"
//     service entry). The blob format is identical so keyholder doesn't
//     care which source produced it.
//
// In --shell mode auth is optional (no agent is running); missing
// credentials are tolerated.
func resolveAuthSecret(agent config.Agent, shell bool) ([]byte, error) {
	switch {
	case agent.AuthCredentialsFile != "":
		path := expandHome(agent.AuthCredentialsFile)
		data, err := os.ReadFile(path) //nolint:gosec // path from validated config
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			if shell {
				return nil, nil
			}
			return nil, fmt.Errorf("read credentials file %s: %w", path, err)
		}
		// File missing — try macOS Keychain.
		if runtime.GOOS == "darwin" {
			blob, kerr := readKeychainCredentials(claudeKeychainService)
			if kerr == nil {
				return blob, nil
			}
			if shell {
				return nil, nil
			}
			return nil, fmt.Errorf("credentials file %s missing and keychain %q lookup failed: %w",
				path, claudeKeychainService, kerr)
		}
		if shell {
			return nil, nil
		}
		return nil, fmt.Errorf("read credentials file %s: %w", path, err)

	case agent.AuthEnv != "":
		v := os.Getenv(agent.AuthEnv)
		if v == "" {
			if shell {
				return nil, nil
			}
			return nil, fmt.Errorf("environment variable %s is not set on the host", agent.AuthEnv)
		}
		return []byte(v + "\n"), nil
	}
	return nil, nil
}

// claudeKeychainService is the macOS Keychain service name the desktop
// claude binary uses for OAuth credentials. Stable as of claude-code 2.1.
const claudeKeychainService = "Claude Code-credentials"

// readKeychainCredentials shells out to `security` to retrieve the blob
// stored at `service` in the user's login keychain. Returns the raw JSON
// bytes (the same format keyholder expects from a credentials file).
func readKeychainCredentials(service string) ([]byte, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("security find-generic-password -s %q: %w", service, err)
	}
	return bytes.TrimRight(out, "\n"), nil
}

// expandHome resolves a leading "~/" or "~" against $HOME.
func expandHome(p string) string {
	if p == "~" {
		h, _ := os.UserHomeDir()
		return h
	}
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, p[2:])
	}
	return p
}

func buildDockerArgv(merged *config.Config, agent config.Agent, agentName string, agentArgs []string, cwd, runID, configDir string, shell bool) ([]string, error) {
	homeDir, _ := os.UserHomeDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	mountFlags := dockerrun.ExpandMounts(claudeDir, agent.Customization)

	// Prepend agent.ExtraArgs so user-supplied CLI args come last and
	// can override (most flag parsers honor last-wins). Shell mode
	// ignores AgentArgs entirely, so ExtraArgs has no effect there.
	fullArgs := make([]string, 0, len(agent.ExtraArgs)+len(agentArgs))
	fullArgs = append(fullArgs, agent.ExtraArgs...)
	fullArgs = append(fullArgs, agentArgs...)

	return dockerrun.BuildArgv(dockerrun.Inputs{
		Config:     merged,
		AgentName:  agentName,
		AgentArgs:  fullArgs,
		CWD:        cwd,
		RunID:      runID,
		ConfigDir:  configDir,
		TTY:        isTerminal(os.Stdin),
		Shell:      shell,
		MountFlags: mountFlags,
	})
}

func pipeAuthSecret(parent context.Context, stderr io.Writer, containerName string, secret []byte) {
	ctx, cancel := context.WithTimeout(parent, keyholderTimeout)
	defer cancel()
	if err := dockerrun.PipeKey(ctx, containerName, string(secret)); err != nil {
		fmt.Fprintln(stderr, "safe: pipe auth secret:", err) //nolint:errcheck // best-effort warning
	}
}

func forwardSignalsToDocker(cmd *exec.Cmd) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	for s := range sigCh {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(s)
		}
	}
}

func waitDocker(cmd *exec.Cmd) error {
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return fmt.Errorf("docker run: %w", err)
	}
	return nil
}

func newRunID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
