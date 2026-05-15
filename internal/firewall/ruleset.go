// Package firewall builds and applies the SAFE nftables ruleset that
// implements the default-deny outbound policy with a dynamic FQDN-anchored
// allow set.
package firewall

import "net"

// Family identifies the nftables address family for a table.
type Family int

const (
	// FamilyINet is the inet (IPv4+IPv6 dual-stack) family.
	FamilyINet Family = iota
)

// Policy is the default verdict for a chain when no rule matches.
type Policy int

const (
	// PolicyDrop drops unmatched traffic.
	PolicyDrop Policy = iota
	// PolicyAccept accepts unmatched traffic (not used by SAFE).
	PolicyAccept
)

// RuleKind enumerates the SAFE-defined rule shapes. Each enum value
// corresponds to exactly one rule emitted by Build; the netlink
// translation lives in apply.go.
type RuleKind int

const (
	// RuleAcceptEstablished accepts established and related connections.
	RuleAcceptEstablished RuleKind = iota
	// RuleAcceptLoopback accepts traffic out the loopback interface.
	RuleAcceptLoopback
	// RuleAcceptLocalhostDNS accepts UDP 53 to 127.0.0.1 (any uid).
	RuleAcceptLocalhostDNS
	// RuleAcceptUpstreamDNS accepts UDP 53 from the firewall uid to the
	// upstream_dns set.
	RuleAcceptUpstreamDNS
	// RuleAcceptAllowedV4 accepts traffic to IPs in the dynamic
	// allowed_v4 set.
	RuleAcceptAllowedV4
	// RuleAcceptAllowedV6 accepts traffic to IPs in the dynamic
	// allowed_v6 set.
	RuleAcceptAllowedV6
)

// Table is the SAFE nftables table.
type Table struct {
	Name   string
	Family Family
}

// Chain is the OUTPUT filter chain.
type Chain struct {
	Name   string
	Policy Policy
}

// Set is a named ipv4/ipv6 set. Dynamic sets accept entries with
// per-element timeouts (used for allowed_v4 / allowed_v6); fixed sets
// hold a pre-loaded element list (used for upstream_dns).
type Set struct {
	Name       string
	IsIPv6     bool
	Dynamic    bool
	HasTimeout bool
	Elements   []net.IP
}

// Rule is one entry in the OUTPUT chain. SourceUID is only meaningful
// for kinds whose semantics include a uid filter.
type Rule struct {
	Kind      RuleKind
	SourceUID uint32
}

// Ruleset is the desired nftables state SAFE will install at startup. It
// is a pure data type: Build returns it, Apply translates it to netlink.
type Ruleset struct {
	Table Table
	Chain Chain
	Sets  map[string]Set
	Rules []Rule
}

// Inputs is everything Build needs from the merged SAFE config.
type Inputs struct {
	UpstreamDNS []net.IP
	FirewallUID uint32
}

// Build computes the deterministic Ruleset for the given inputs. It does
// not touch the kernel.
func Build(in Inputs) Ruleset {
	upstreamV4 := make([]net.IP, 0, len(in.UpstreamDNS))
	for _, ip := range in.UpstreamDNS {
		if v4 := ip.To4(); v4 != nil {
			upstreamV4 = append(upstreamV4, v4)
		}
	}

	return Ruleset{
		Table: Table{Name: "safe", Family: FamilyINet},
		Chain: Chain{Name: "output", Policy: PolicyDrop},
		Sets: map[string]Set{
			"allowed_v4":   {Name: "allowed_v4", Dynamic: true, HasTimeout: true},
			"allowed_v6":   {Name: "allowed_v6", IsIPv6: true, Dynamic: true, HasTimeout: true},
			"upstream_dns": {Name: "upstream_dns", Elements: upstreamV4},
		},
		Rules: []Rule{
			{Kind: RuleAcceptEstablished},
			{Kind: RuleAcceptLoopback},
			{Kind: RuleAcceptLocalhostDNS},
			{Kind: RuleAcceptUpstreamDNS, SourceUID: in.FirewallUID},
			{Kind: RuleAcceptAllowedV4},
			{Kind: RuleAcceptAllowedV6},
		},
	}
}
