package firewall

import (
	"fmt"
	"strings"
)

// Render serializes the Ruleset to an `nft` script suitable for piping
// into `nft -f -`. Output is deterministic so it can be golden-tested.
//
// We render via text rather than wire-formatting netlink ourselves because
// (a) the container ships the `nft` binary anyway, (b) text is far easier
// to debug when something goes wrong, and (c) the kernel does all the
// validation. The performance cost of one-time setup is irrelevant.
func Render(rs Ruleset) string {
	var sb strings.Builder
	sb.WriteString("flush ruleset\n")
	fmt.Fprintf(&sb, "table %s %s {\n", familyToken(rs.Table.Family), rs.Table.Name)

	renderSet(&sb, rs.Sets["allowed_v4"])
	renderSet(&sb, rs.Sets["allowed_v6"])
	renderSet(&sb, rs.Sets["upstream_dns"])

	fmt.Fprintf(&sb, "\tchain %s {\n", rs.Chain.Name)
	fmt.Fprintf(&sb, "\t\ttype filter hook output priority filter; policy %s;\n", policyToken(rs.Chain.Policy))
	for _, r := range rs.Rules {
		sb.WriteString("\t\t")
		sb.WriteString(renderRule(r))
		sb.WriteString("\n")
	}
	sb.WriteString("\t}\n")
	sb.WriteString("}\n")
	return sb.String()
}

func renderSet(sb *strings.Builder, s Set) {
	if s.Name == "" {
		return
	}
	addrType := "ipv4_addr"
	if s.IsIPv6 {
		addrType = "ipv6_addr"
	}
	fmt.Fprintf(sb, "\tset %s {\n", s.Name)
	fmt.Fprintf(sb, "\t\ttype %s\n", addrType)
	switch {
	case s.Dynamic && s.HasTimeout:
		sb.WriteString("\t\tflags timeout, dynamic\n")
	case s.Dynamic:
		sb.WriteString("\t\tflags dynamic\n")
	}
	if len(s.Elements) > 0 {
		parts := make([]string, 0, len(s.Elements))
		for _, ip := range s.Elements {
			parts = append(parts, ip.String())
		}
		fmt.Fprintf(sb, "\t\telements = { %s }\n", strings.Join(parts, ", "))
	}
	sb.WriteString("\t}\n")
}

func renderRule(r Rule) string {
	switch r.Kind {
	case RuleAcceptEstablished:
		return "ct state established,related accept"
	case RuleAcceptLoopback:
		return `oif "lo" accept`
	case RuleAcceptLocalhostDNS:
		return "udp dport 53 ip daddr 127.0.0.1 accept"
	case RuleAcceptUpstreamDNS:
		return fmt.Sprintf("meta skuid %d udp dport 53 ip daddr @upstream_dns accept", r.SourceUID)
	case RuleAcceptAllowedV4:
		return "ip daddr @allowed_v4 accept"
	case RuleAcceptAllowedV6:
		return "ip6 daddr @allowed_v6 accept"
	default:
		// Unknown kinds drop into a no-op comment so the script stays
		// syntactically valid; the unit tests cover every known kind so
		// this branch should never run in practice.
		return fmt.Sprintf("# unknown rule kind %d", r.Kind)
	}
}

func familyToken(f Family) string {
	switch f {
	case FamilyINet:
		return "inet"
	default:
		return "inet"
	}
}

func policyToken(p Policy) string {
	switch p {
	case PolicyDrop:
		return "drop"
	case PolicyAccept:
		return "accept"
	default:
		return "drop"
	}
}
