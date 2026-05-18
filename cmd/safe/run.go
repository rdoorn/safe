package main

import (
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
	"strings"
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/dockerrun"
	"gopkg.in/yaml.v3"
)

const (
	keyholderSocketFile = "keyholder.sock"
	keyholderTimeout    = 10 * time.Second
)

// runAgent is the path executed when the user runs `safe <agent> [args...]`.
// It loads/validates config, prepares the per-run state, and execs docker.
func runAgent(ctx context.Context, stdout, stderr io.Writer, xdgConfigDir, cwd, agentName string, agentArgs []string, shell bool) error {
	merged, agent, err := loadAgent(xdgConfigDir, cwd, agentName)
	if err != nil {
		return err
	}

	secret, err := resolveAuthSecret(agent, shell)
	if err != nil {
		return err
	}

	runID := newRunID()
	runRoot := filepath.Join(cwd, ".safe", runID)
	if err := os.MkdirAll(runRoot, 0o755); err != nil { //nolint:gosec // 0o755 is intentional; container uids must traverse
		return fmt.Errorf("create run dir %s: %w", runRoot, err)
	}
	defer func() { _ = os.RemoveAll(runRoot) }()

	socketDir := filepath.Join(runRoot, "socket")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := dockerrun.PrepareSocketDir(socketDir); err != nil {
		return err
	}

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

	argv, err := buildDockerArgv(merged, agent, agentName, agentArgs, cwd, runID, socketDir, configDir, shell)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv constructed from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start docker: %w", err)
	}

	if !shell && len(secret) > 0 {
		go pipeAuthSecret(ctx, stderr, filepath.Join(socketDir, keyholderSocketFile), secret)
	}
	go forwardSignalsToDocker(cmd)

	return waitDocker(cmd)
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
//   - OAuth mode: returns the raw JSON contents of the credentials file.
//
// In --shell mode auth is optional (no agent is running); missing
// credentials are tolerated.
func resolveAuthSecret(agent config.Agent, shell bool) ([]byte, error) {
	switch {
	case agent.AuthCredentialsFile != "":
		path := expandHome(agent.AuthCredentialsFile)
		data, err := os.ReadFile(path) //nolint:gosec // path from validated config
		if err != nil {
			if shell {
				return nil, nil
			}
			return nil, fmt.Errorf("read credentials file %s: %w", path, err)
		}
		return data, nil

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

func buildDockerArgv(merged *config.Config, agent config.Agent, agentName string, agentArgs []string, cwd, runID, socketDir, configDir string, shell bool) ([]string, error) {
	homeDir, _ := os.UserHomeDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	mountFlags := dockerrun.ExpandMounts(claudeDir, agent.Customization)

	return dockerrun.BuildArgv(dockerrun.Inputs{
		Config:     merged,
		AgentName:  agentName,
		AgentArgs:  agentArgs,
		CWD:        cwd,
		RunID:      runID,
		SocketDir:  socketDir,
		ConfigDir:  configDir,
		TTY:        isTerminal(os.Stdin),
		Shell:      shell,
		MountFlags: mountFlags,
	})
}

func pipeAuthSecret(parent context.Context, stderr io.Writer, socketPath string, secret []byte) {
	ctx, cancel := context.WithTimeout(parent, keyholderTimeout)
	defer cancel()
	if err := dockerrun.PipeKey(ctx, socketPath, string(secret)); err != nil {
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
