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
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/dockerrun"
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

	apiKey, err := resolveAPIKey(agent, shell)
	if err != nil {
		return err
	}

	socketDir, cleanupSocket, err := dockerrun.NewSocketDir("safe-")
	if err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	defer cleanupSocket()

	argv, err := buildDockerArgv(merged, agent, agentName, agentArgs, cwd, socketDir, shell)
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

	if !shell && apiKey != "" {
		go pipeAPIKey(ctx, stderr, filepath.Join(socketDir, keyholderSocketFile), apiKey)
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

func resolveAPIKey(agent config.Agent, shell bool) (string, error) {
	if agent.AuthEnv == "" {
		return "", nil
	}
	v := os.Getenv(agent.AuthEnv)
	if v == "" && !shell {
		return "", fmt.Errorf("environment variable %s is not set on the host", agent.AuthEnv)
	}
	return v, nil
}

func buildDockerArgv(merged *config.Config, agent config.Agent, agentName string, agentArgs []string, cwd, socketDir string, shell bool) ([]string, error) {
	homeDir, _ := os.UserHomeDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	mountFlags := dockerrun.ExpandMounts(claudeDir, agent.Customization)

	return dockerrun.BuildArgv(dockerrun.Inputs{
		Config:     merged,
		AgentName:  agentName,
		AgentArgs:  agentArgs,
		CWD:        cwd,
		RunID:      newRunID(),
		SocketDir:  socketDir,
		TTY:        isTerminal(os.Stdin),
		Shell:      shell,
		MountFlags: mountFlags,
	})
}

func pipeAPIKey(parent context.Context, stderr io.Writer, socketPath, apiKey string) {
	ctx, cancel := context.WithTimeout(parent, keyholderTimeout)
	defer cancel()
	if err := dockerrun.PipeKey(ctx, socketPath, apiKey); err != nil {
		fmt.Fprintln(stderr, "safe: pipe api key:", err) //nolint:errcheck // best-effort warning
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
