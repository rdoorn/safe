package main

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMarshalMergedConfigRoundtrips(t *testing.T) {
	in := &config.Config{
		UpstreamDNS: []string{"1.1.1.1", "9.9.9.9"},
		Allowlist:   []string{"api.anthropic.com"},
		Agents: map[string]config.Agent{
			"claude": {
				Image:       "ghcr.io/example/safe-runtime:0.1.0",
				Entrypoint:  "claude",
				AuthEnv:     "ANTHROPIC_API_KEY",
				BaseURL:     "https://api.anthropic.com",
				LockedTools: []string{"Read"},
			},
		},
	}
	data, err := yaml.Marshal(in)
	require.NoError(t, err)

	out, err := config.Parse(data)
	require.NoError(t, err)
	require.Equal(t, in.UpstreamDNS, out.UpstreamDNS)
	require.Equal(t, in.Allowlist, out.Allowlist)
	require.Equal(t, in.Agents["claude"].Image, out.Agents["claude"].Image)
}
