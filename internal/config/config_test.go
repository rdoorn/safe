package config_test

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func TestParseMinimalConfig(t *testing.T) {
	src := `
agents:
  claude:
    image: ghcr.io/example/safe-runtime:0.1.0
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
allowlist:
  - api.anthropic.com
upstream_dns:
  - 1.1.1.1
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.Equal(t, "claude", cfg.Agents["claude"].Entrypoint)
	require.Equal(t, "ghcr.io/example/safe-runtime:0.1.0", cfg.Agents["claude"].Image)
	require.Equal(t, "ANTHROPIC_API_KEY", cfg.Agents["claude"].AuthEnv)
	require.Equal(t, "https://api.anthropic.com", cfg.Agents["claude"].BaseURL)
	require.Equal(t, []string{"api.anthropic.com"}, cfg.Allowlist)
	require.Equal(t, []string{"1.1.1.1"}, cfg.UpstreamDNS)
}

func TestParseEmptyConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(""))
	require.NoError(t, err)
	require.Empty(t, cfg.Agents)
	require.Empty(t, cfg.Allowlist)
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := config.Parse([]byte("agents: [this: is: invalid"))
	require.Error(t, err)
}

func TestParseRTKEnabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
rtk:
  enabled: true
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.True(t, cfg.RTK.IsEnabled())
}

func TestParseRTKDisabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
rtk:
  enabled: false
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.False(t, cfg.RTK.IsEnabled())
}

func TestParseRTKAbsentDefaultsToEnabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.True(t, cfg.RTK.IsEnabled(), "absent rtk block must default to enabled")
}

func TestParseCustomization(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    customization:
      skills: true
      hooks: false
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.True(t, cfg.Agents["claude"].Customization.Skills)
	require.False(t, cfg.Agents["claude"].Customization.Hooks)
}
