package checks_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rdoorn/safe/internal/checks"
	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

type fakeDocker struct {
	versionErr   error
	imageMissing bool
	imageRef     string
}

func (f *fakeDocker) Version(_ context.Context) (string, error) {
	if f.versionErr != nil {
		return "", f.versionErr
	}
	return "Docker version 26.0.0", nil
}

func (f *fakeDocker) ImageExists(_ context.Context, ref string) (bool, error) {
	f.imageRef = ref
	return !f.imageMissing, nil
}

type fakeEnv map[string]string

func (e fakeEnv) Lookup(k string) (string, bool) {
	v, ok := e[k]
	return v, ok
}

func validConfig() *config.Config {
	return &config.Config{
		Agents: map[string]config.Agent{
			"claude": {
				Image:       "ghcr.io/example/safe-runtime:0.1.0",
				Entrypoint:  "claude",
				AuthEnv:     "ANTHROPIC_API_KEY",
				BaseURL:     "https://api.anthropic.com",
				LockedTools: []string{"Read"},
			},
		},
		Allowlist:   []string{"api.anthropic.com"},
		UpstreamDNS: []string{"1.1.1.1"},
	}
}

func TestDoctorAllGreen(t *testing.T) {
	results := checks.Run(
		context.Background(),
		checks.Deps{Docker: &fakeDocker{}, Env: fakeEnv{"ANTHROPIC_API_KEY": "sk-test"}},
		validConfig(),
		"claude",
	)
	for _, r := range results {
		require.True(t, r.OK, "check %q failed: %s", r.Name, r.Detail)
	}
}

func TestDoctorDockerUnreachable(t *testing.T) {
	results := checks.Run(
		context.Background(),
		checks.Deps{Docker: &fakeDocker{versionErr: errors.New("connect: refused")}, Env: fakeEnv{"ANTHROPIC_API_KEY": "x"}},
		validConfig(),
		"claude",
	)
	var dockerCheck *checks.Result
	for i, r := range results {
		if r.Name == "docker reachable" {
			dockerCheck = &results[i]
		}
	}
	require.NotNil(t, dockerCheck)
	require.False(t, dockerCheck.OK)
	require.Contains(t, dockerCheck.Detail, "refused")
}

func TestDoctorImageMissing(t *testing.T) {
	results := checks.Run(
		context.Background(),
		checks.Deps{Docker: &fakeDocker{imageMissing: true}, Env: fakeEnv{"ANTHROPIC_API_KEY": "x"}},
		validConfig(),
		"claude",
	)
	var c *checks.Result
	for i, r := range results {
		if r.Name == "image present" {
			c = &results[i]
		}
	}
	require.NotNil(t, c)
	require.False(t, c.OK)
}

func TestDoctorAPIKeyMissing(t *testing.T) {
	results := checks.Run(
		context.Background(),
		checks.Deps{Docker: &fakeDocker{}, Env: fakeEnv{}},
		validConfig(),
		"claude",
	)
	var c *checks.Result
	for i, r := range results {
		if r.Name == "ANTHROPIC_API_KEY set" {
			c = &results[i]
		}
	}
	require.NotNil(t, c)
	require.False(t, c.OK)
}

func TestDoctorConfigInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.UpstreamDNS = nil
	results := checks.Run(
		context.Background(),
		checks.Deps{Docker: &fakeDocker{}, Env: fakeEnv{"ANTHROPIC_API_KEY": "x"}},
		cfg,
		"claude",
	)
	var c *checks.Result
	for i, r := range results {
		if r.Name == "config valid" {
			c = &results[i]
		}
	}
	require.NotNil(t, c)
	require.False(t, c.OK)
}
