package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// KnownAgentTools is the set of Claude Code tool names the validator will
// accept in `agents.<name>.locked_tools`. Adding new agent runtimes will
// require expanding this list (or making it per-agent).
var KnownAgentTools = map[string]struct{}{
	"Read":         {},
	"Write":        {},
	"Edit":         {},
	"Bash":         {},
	"Glob":         {},
	"Grep":         {},
	"NotebookEdit": {},
	"Task":         {},
	"WebFetch":     {},
	"WebSearch":    {},
	"TodoWrite":    {},
}

// fqdnPattern matches an absolute domain name in lowercase form, with an
// optional leading "*." wildcard as the leftmost label only.
var fqdnPattern = regexp.MustCompile(`^(\*\.)?([a-z0-9](-?[a-z0-9])*)(\.[a-z0-9](-?[a-z0-9])*)+$`)

// Validate checks the merged config against SAFE's invariants for an
// invocation that targets the given agent name. It returns the first
// problem it finds; callers should fix that and re-validate (no error
// accumulation in v1, to keep messages punchy).
func Validate(c *Config, agentName string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	if err := validateAllowlist(c.Allowlist); err != nil {
		return err
	}

	if len(c.UpstreamDNS) == 0 {
		return errors.New("upstream_dns must list at least one resolver")
	}

	agent, ok := c.Agents[agentName]
	if !ok {
		return fmt.Errorf("agent %q is not in the agents registry", agentName)
	}

	if err := validateAgent(agentName, agent); err != nil {
		return err
	}

	return validateBaseURLAllowlisted(agent.BaseURL, c.Allowlist)
}

func validateAllowlist(entries []string) error {
	for _, e := range entries {
		lower := strings.ToLower(e)
		if !fqdnPattern.MatchString(lower) {
			return fmt.Errorf("allowlist entry %q is not a valid FQDN or *.fqdn pattern", e)
		}
	}
	return nil
}

func validateAgent(name string, a Agent) error {
	if a.Image == "" {
		return fmt.Errorf("agent %q: image is required", name)
	}
	if a.Entrypoint == "" {
		return fmt.Errorf("agent %q: entrypoint is required", name)
	}
	if len(a.LockedTools) == 0 {
		return fmt.Errorf("agent %q: locked_tools must list at least one tool", name)
	}
	for _, t := range a.LockedTools {
		if _, ok := KnownAgentTools[t]; !ok {
			return fmt.Errorf("agent %q: locked_tools contains unknown tool %q", name, t)
		}
	}
	if a.BaseURL != "" {
		if _, err := url.Parse(a.BaseURL); err != nil {
			return fmt.Errorf("agent %q: base_url %q is unparseable: %w", name, a.BaseURL, err)
		}
		u, _ := url.Parse(a.BaseURL)
		if u.Host == "" {
			return fmt.Errorf("agent %q: base_url %q has no host", name, a.BaseURL)
		}
	}
	return nil
}

func validateBaseURLAllowlisted(baseURL string, allowlist []string) error {
	if baseURL == "" {
		return nil
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("base_url %q has no host", baseURL)
	}
	host := strings.ToLower(u.Hostname())
	for _, entry := range allowlist {
		if matchAllowlistEntry(strings.ToLower(entry), host) {
			return nil
		}
	}
	return fmt.Errorf("agent base_url host %q is not in allowlist", host)
}

// matchAllowlistEntry returns true if host matches the entry, which may be
// either an exact FQDN or a "*.suffix" wildcard.
func matchAllowlistEntry(entry, host string) bool {
	if strings.HasPrefix(entry, "*.") {
		suffix := entry[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}
	return entry == host
}
