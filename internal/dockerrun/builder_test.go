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
		ConfigDir:      "/tmp/safe-cfg-x",
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
	require.NotContains(t, joined, "no-new-privileges", "no-new-privileges breaks file caps; agent isolation is via 0750 perms")
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
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-v /Users/user/myproject:/workspace")
}

func TestBuildArgvPublishesBootstrapPort(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-p 127.0.0.1:0:9099/tcp")
}

func TestBuildArgvDoesNotBindRunSafe(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.NotContains(t, strings.Join(argv, " "), "/run/safe",
		"socket dir bind mount has been replaced by TCP loopback")
}

func TestBuildArgvAgentNotInConfig(t *testing.T) {
	_, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "ghost",
		CWD:       "/p",
		RunID:     "x",
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
		ConfigDir: "/tmp/safe-cfg-x",
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
		ConfigDir: "/tmp/safe-cfg-x",
		Shell:     true,
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	// In shell mode the container's entrypoint is overridden so the user
	// lands directly in bash instead of going through safe-init.
	require.Contains(t, joined, "--entrypoint /bin/bash")
	require.NotContains(t, joined, "claude hello")
}

func TestBuildArgvBindsConfigDir(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-v /tmp/safe-cfg-x:/etc/safe:ro")
}

func TestBuildArgvRequiresConfigDir(t *testing.T) {
	_, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		// ConfigDir intentionally omitted
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "config dir")
}

func TestBuildArgvIncludesRequiredCaps(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	for _, c := range []string{"NET_ADMIN", "SETUID", "SETGID", "KILL"} {
		require.Contains(t, joined, "--cap-add "+c,
			"%s must be in the required cap set: SAFE's uid-separation architecture cannot function without it", c)
	}
}

func TestBuildArgvAppendsExtraCaps(t *testing.T) {
	cfg := minimalConfig()
	cfg.ExtraCaps = []string{"SYS_ADMIN", "SYS_PTRACE"}
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "--cap-add SYS_ADMIN")
	require.Contains(t, joined, "--cap-add SYS_PTRACE")
}

func TestBuildArgvNoExtraCapsByDefault(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.NotContains(t, joined, "--cap-add SYS_ADMIN",
		"extra caps must be opt-in only")
	require.NotContains(t, joined, "--cap-add SYS_PTRACE")
}

func TestBuildArgvSetsBaseURLEnvDefault(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-e ANTHROPIC_BASE_URL=http://127.0.0.1:8443")
}

func TestBuildArgvSetsBaseURLEnvCustomName(t *testing.T) {
	cfg := minimalConfig()
	a := cfg.Agents["claude"]
	a.BaseURLEnv = "CUSTOM_BASE_URL_VAR"
	cfg.Agents["claude"] = a

	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "-e CUSTOM_BASE_URL_VAR=http://127.0.0.1:8443")
	require.NotContains(t, joined, "-e ANTHROPIC_BASE_URL=", "default name must not also be emitted when custom is set")
}

func TestBuildArgvSetsDummyAuthEnvInAPIKeyMode(t *testing.T) {
	cfg := minimalConfig()
	a := cfg.Agents["claude"]
	a.AuthEnv = "ANTHROPIC_API_KEY"
	cfg.Agents["claude"] = a

	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-e ANTHROPIC_API_KEY=dummy")
}

func TestBuildArgvSkipsDummyAuthEnvInOAuthMode(t *testing.T) {
	cfg := minimalConfig()
	a := cfg.Agents["claude"]
	a.AuthEnv = ""
	a.AuthCredentialsFile = "/some/path/credentials.json"
	cfg.Agents["claude"] = a

	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.NotContains(t, strings.Join(argv, " "), "=dummy",
		"OAuth mode has no AuthEnv to dummy out")
}

func TestBuildArgvPassesAgentEnvBlock(t *testing.T) {
	cfg := minimalConfig()
	a := cfg.Agents["claude"]
	a.Env = map[string]string{
		"DISABLE_TELEMETRY":               "1",
		"CLAUDE_CODE_DISABLE_AUTOUPDATER": "1",
	}
	cfg.Agents["claude"] = a

	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "-e CLAUDE_CODE_DISABLE_AUTOUPDATER=1")
	require.Contains(t, joined, "-e DISABLE_TELEMETRY=1")
}

func TestBuildArgvTmpfsForAuditLog(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "--tmpfs /var/log/safe:rw,nosuid,nodev,uid=200,gid=200,size=64m",
		"safe-dns audit log needs a writable tmpfs since rootfs is read-only")
}
