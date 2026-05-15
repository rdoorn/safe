package dockerrun_test

import (
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func minimalConfig() *config.Config {
	return &config.Config{
		Agents: map[string]config.Agent{
			"claude": {
				Image:      "ghcr.io/example/safe-runtime:0.1.0",
				Entrypoint: "claude",
			},
		},
	}
}

func TestBuildArgvHasHardeningFlags(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:         minimalConfig(),
		AgentName:      "claude",
		AgentArgs:      []string{"hello"},
		CWD:            "/Users/user/project",
		RunID:          "run-abc123",
		SocketDir:      "/tmp/safe-abc123",
		TTY:            true,
		SeccompProfile: "/etc/safe/seccomp.json",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")

	require.Contains(t, joined, "docker run")
	require.Contains(t, joined, "--rm")
	require.Contains(t, joined, "-it")
	require.Contains(t, joined, "--cap-drop ALL")
	require.Contains(t, joined, "--cap-add NET_ADMIN")
	require.Contains(t, joined, "--security-opt no-new-privileges")
	require.Contains(t, joined, "--security-opt seccomp=/etc/safe/seccomp.json")
	require.Contains(t, joined, "--read-only")
	require.Contains(t, joined, "--dns 127.0.0.1")
	require.Contains(t, joined, "ghcr.io/example/safe-runtime:0.1.0 claude hello")
}

func TestBuildArgvBindsWorkspace(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/Users/user/myproject",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-v /Users/user/myproject:/workspace")
}

func TestBuildArgvBindsSocketDir(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-v /tmp/safe-x:/run/safe")
}

func TestBuildArgvAgentNotInConfig(t *testing.T) {
	_, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "ghost",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ghost")
}

func TestBuildArgvOnlyAllowedEnvPassthrough(t *testing.T) {
	cfg := minimalConfig()
	cfg.EnvPassthrough = []string{"TERM", "LANG"}
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "-e TERM")
	require.Contains(t, joined, "-e LANG")
	require.NotContains(t, joined, "-e HOME")
}

func TestBuildArgvShellMode(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		Shell:     true,
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	// In shell mode the container's entrypoint is overridden so the user
	// lands directly in bash instead of going through safe-init.
	require.Contains(t, joined, "--entrypoint /bin/bash")
	require.NotContains(t, joined, "claude hello")
}
