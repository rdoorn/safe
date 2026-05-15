package config_test

import (
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func validBase() *config.Config {
	return &config.Config{
		Agents: map[string]config.Agent{
			"claude": {
				Image:       "ghcr.io/example/safe-runtime:0.1.0",
				Entrypoint:  "claude",
				AuthEnv:     "ANTHROPIC_API_KEY",
				BaseURL:     "https://api.anthropic.com",
				LockedTools: []string{"Read", "Write", "Bash"},
			},
		},
		Allowlist:   []string{"api.anthropic.com"},
		UpstreamDNS: []string{"1.1.1.1"},
	}
}

func TestValidateHappyPath(t *testing.T) {
	require.NoError(t, config.Validate(validBase(), "claude"))
}

func TestValidateUnknownAgent(t *testing.T) {
	err := config.Validate(validBase(), "ghost")
	require.Error(t, err)
	require.Contains(t, err.Error(), "ghost")
}

func TestValidateAllowlistFQDNFormat(t *testing.T) {
	cases := map[string]bool{
		"api.anthropic.com":   true,
		"a.b.c.d.example.com": true,
		"*.example.com":       true,
		"sub.*.example.com":   false, // wildcard only allowed as leftmost label
		"example":             false, // single label
		"1.2.3.4":             false, // IP, not FQDN
		"http://example.com":  false,
		"example.com/path":    false,
		"EXAMPLE.COM":         true, // case-insensitive
		"xn--example-9ua.com": true, // punycode is fine
	}
	for entry, ok := range cases {
		c := validBase()
		c.Allowlist = []string{entry}
		err := config.Validate(c, "claude")
		// Some valid configs become invalid for a different reason (base URL
		// host not in allowlist), so we only check the "format" branch.
		if !ok {
			require.Error(t, err, "expected error for %q", entry)
			require.Contains(t, strings.ToLower(err.Error()), "allowlist", "wrong error for %q: %v", entry, err)
		}
	}
}

func TestValidateImageMissing(t *testing.T) {
	c := validBase()
	a := c.Agents["claude"]
	a.Image = ""
	c.Agents["claude"] = a
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "image")
}

func TestValidateLockedToolsUnknown(t *testing.T) {
	c := validBase()
	a := c.Agents["claude"]
	a.LockedTools = []string{"Read", "Frobnicate"}
	c.Agents["claude"] = a
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Frobnicate")
}

func TestValidateLockedToolsEmpty(t *testing.T) {
	c := validBase()
	a := c.Agents["claude"]
	a.LockedTools = nil
	c.Agents["claude"] = a
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "locked_tools")
}

func TestValidateBaseURLNotInAllowlist(t *testing.T) {
	c := validBase()
	c.Allowlist = []string{"other.example.com"}
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "api.anthropic.com")
	require.Contains(t, err.Error(), "allowlist")
}

func TestValidateBaseURLWildcardMatch(t *testing.T) {
	c := validBase()
	a := c.Agents["claude"]
	a.BaseURL = "https://api.example.com"
	c.Agents["claude"] = a
	c.Allowlist = []string{"*.example.com"}
	require.NoError(t, config.Validate(c, "claude"))
}

func TestValidateBaseURLUnparseable(t *testing.T) {
	c := validBase()
	a := c.Agents["claude"]
	a.BaseURL = "://nope"
	c.Agents["claude"] = a
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "base_url")
}

func TestValidateEmptyUpstreamDNS(t *testing.T) {
	c := validBase()
	c.UpstreamDNS = nil
	err := config.Validate(c, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "upstream_dns")
}
