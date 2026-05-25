package config_test

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func TestMergeArraysAppend(t *testing.T) {
	base := &config.Config{Allowlist: []string{"a.example.com"}}
	overlay := &config.Config{Allowlist: []string{"b.example.com"}}

	got := config.Merge(base, overlay)
	require.Equal(t, []string{"a.example.com", "b.example.com"}, got.Allowlist)
}

func TestMergeScalarReplace(t *testing.T) {
	base := &config.Config{
		Resources: config.Resources{Memory: "2g", PIDs: 128},
	}
	overlay := &config.Config{
		Resources: config.Resources{Memory: "8g"}, // PIDs left zero
	}

	got := config.Merge(base, overlay)
	require.Equal(t, "8g", got.Resources.Memory)
	require.Equal(t, 128, got.Resources.PIDs, "zero overlay value must NOT replace base")
}

func TestMergeAgentsByName(t *testing.T) {
	base := &config.Config{
		Agents: map[string]config.Agent{
			"claude":   {Image: "old", Entrypoint: "claude"},
			"opencode": {Image: "opencode-image"},
		},
	}
	overlay := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Image: "new"},
		},
	}

	got := config.Merge(base, overlay)
	require.Equal(t, "new", got.Agents["claude"].Image)
	require.Equal(t, "claude", got.Agents["claude"].Entrypoint, "non-overridden fields preserved")
	require.Equal(t, "opencode-image", got.Agents["opencode"].Image, "unrelated agents preserved")
}

func TestMergeAgentLockedToolsAppend(t *testing.T) {
	base := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {LockedTools: []string{"Read", "Write"}},
		},
	}
	overlay := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {LockedTools: []string{"Bash"}},
		},
	}

	got := config.Merge(base, overlay)
	require.Equal(t, []string{"Read", "Write", "Bash"}, got.Agents["claude"].LockedTools)
}

func TestMergeAgentEnvPerKey(t *testing.T) {
	base := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Env: map[string]string{"A": "1", "B": "2"}},
		},
	}
	overlay := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Env: map[string]string{"A": "override", "C": "3"}},
		},
	}

	got := config.Merge(base, overlay)
	require.Equal(t, map[string]string{"A": "override", "B": "2", "C": "3"}, got.Agents["claude"].Env)
}

func TestMergeCustomizationReplacesWholeStructIfSet(t *testing.T) {
	tr := true
	base := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Customization: config.Customization{Skills: tr, Hooks: tr}},
		},
	}
	overlay := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Customization: config.Customization{Commands: tr}}, // skills, hooks now off
		},
	}

	got := config.Merge(base, overlay)
	// Whole-struct replace semantics: overlay's Customization wins entirely
	// when any field is set.
	require.False(t, got.Agents["claude"].Customization.Skills)
	require.True(t, got.Agents["claude"].Customization.Commands)
	require.False(t, got.Agents["claude"].Customization.Hooks)
}

func TestMergeCustomizationKeepsBaseIfOverlayZero(t *testing.T) {
	tr := true
	base := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Customization: config.Customization{Skills: tr}},
		},
	}
	overlay := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {Image: "x"}, // no Customization at all
		},
	}

	got := config.Merge(base, overlay)
	require.True(t, got.Agents["claude"].Customization.Skills, "base preserved when overlay didn't touch")
}

func TestMergeNilInputs(t *testing.T) {
	require.NotPanics(t, func() {
		_ = config.Merge(nil, nil)
		_ = config.Merge(&config.Config{}, nil)
		_ = config.Merge(nil, &config.Config{})
	})
}

func TestMergeRTKOverlayDisables(t *testing.T) {
	yes := true
	no := false
	base := &config.Config{RTK: config.RTK{Enabled: &yes}}
	overlay := &config.Config{RTK: config.RTK{Enabled: &no}}
	out := config.Merge(base, overlay)
	require.False(t, out.RTK.IsEnabled())
}

func TestMergeRTKOverlayAbsentPreservesBase(t *testing.T) {
	yes := true
	base := &config.Config{RTK: config.RTK{Enabled: &yes}}
	overlay := &config.Config{}
	out := config.Merge(base, overlay)
	require.True(t, out.RTK.IsEnabled())
}

func TestMergeChainViaLoadAll(t *testing.T) {
	got := config.MergeAll([]*config.Config{
		{Allowlist: []string{"a"}},
		{Allowlist: []string{"b"}},
		{Allowlist: []string{"c"}},
	})
	require.Equal(t, []string{"a", "b", "c"}, got.Allowlist)
}
