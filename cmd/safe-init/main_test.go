package main

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func TestResolveAuthModeAPIKey(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {AuthEnv: "ANTHROPIC_API_KEY"},
		},
	}
	mode, err := resolveAuthMode(cfg, "claude")
	require.NoError(t, err)
	require.Equal(t, "apikey", mode)
}

func TestResolveAuthModeOAuth(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {AuthCredentialsFile: "/home/user/.claude/.credentials.json"},
		},
	}
	mode, err := resolveAuthMode(cfg, "claude")
	require.NoError(t, err)
	require.Equal(t, "oauth", mode)
}

func TestResolveAuthModeUnknownAgent(t *testing.T) {
	cfg := &config.Config{Agents: map[string]config.Agent{}}
	_, err := resolveAuthMode(cfg, "unknown")
	require.Error(t, err)
}
