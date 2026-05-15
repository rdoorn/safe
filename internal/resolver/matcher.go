// Package resolver implements safe-dns: the FQDN-allowlist DNS resolver
// that dynamically installs nftables rules as the agent looks up allowed
// hostnames.
package resolver

import "strings"

// Matcher decides whether a DNS query name is on the SAFE allowlist.
// Entries are either exact FQDNs ("api.anthropic.com") or wildcard
// suffixes ("*.example.com" — matches any name with at least one label
// before ".example.com" but NOT the apex). Matching is case-insensitive
// and ignores a single trailing root dot.
type Matcher struct {
	exact     map[string]struct{}
	wildcards []string // stored as ".example.com" (leading dot, no leading "*")
}

// NewMatcher builds a Matcher from the merged allowlist.
func NewMatcher(entries []string) *Matcher {
	m := &Matcher{exact: map[string]struct{}{}}
	for _, e := range entries {
		norm := normalize(e)
		if norm == "" {
			continue
		}
		if strings.HasPrefix(norm, "*.") {
			m.wildcards = append(m.wildcards, norm[1:]) // ".example.com"
		} else {
			m.exact[norm] = struct{}{}
		}
	}
	return m
}

// Allows reports whether name passes the allowlist. The DNS server calls
// this on every query before forwarding upstream.
func (m *Matcher) Allows(name string) bool {
	n := normalize(name)
	if n == "" {
		return false
	}
	if _, ok := m.exact[n]; ok {
		return true
	}
	for _, suffix := range m.wildcards {
		if strings.HasSuffix(n, suffix) && n != suffix[1:] {
			return true
		}
	}
	return false
}

// normalize lowercases and strips a single trailing dot.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	return s
}
