package firewall_test

import (
	"net"
	"testing"

	"github.com/rdoorn/safe/internal/firewall"
	"github.com/stretchr/testify/require"
)

func TestBuildRulesetTableAndChain(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 100,
	})

	require.Equal(t, "safe", rs.Table.Name)
	require.Equal(t, firewall.FamilyINet, rs.Table.Family)
	require.Equal(t, "output", rs.Chain.Name)
	require.Equal(t, firewall.PolicyDrop, rs.Chain.Policy)
}

func TestBuildRulesetSets(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")},
		FirewallUID: 100,
	})

	require.Contains(t, rs.Sets, "allowed_v4")
	require.True(t, rs.Sets["allowed_v4"].Dynamic)
	require.True(t, rs.Sets["allowed_v4"].HasTimeout)

	require.Contains(t, rs.Sets, "allowed_v6")
	require.True(t, rs.Sets["allowed_v6"].Dynamic)

	require.Contains(t, rs.Sets, "upstream_dns")
	require.False(t, rs.Sets["upstream_dns"].Dynamic, "upstream_dns is a fixed allowlist")
	require.Len(t, rs.Sets["upstream_dns"].Elements, 2)
}

func TestBuildRulesetOutputRulesInOrder(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 100,
	})

	require.GreaterOrEqual(t, len(rs.Rules), 6)
	require.Equal(t, firewall.RuleAcceptEstablished, rs.Rules[0].Kind)
	require.Equal(t, firewall.RuleAcceptLoopback, rs.Rules[1].Kind)
	require.Equal(t, firewall.RuleAcceptLocalhostDNS, rs.Rules[2].Kind)
	require.Equal(t, firewall.RuleAcceptUpstreamDNS, rs.Rules[3].Kind)
	require.Equal(t, uint32(100), rs.Rules[3].SourceUID, "upstream DNS rule is scoped to firewall uid")
	require.Equal(t, firewall.RuleAcceptAllowedV4, rs.Rules[4].Kind)
	require.Equal(t, firewall.RuleAcceptAllowedV6, rs.Rules[5].Kind)
}

func TestBuildRulesetUpstreamDNSElementsAreIPv4(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2001:4860:4860::8888")},
		FirewallUID: 100,
	})

	for _, e := range rs.Sets["upstream_dns"].Elements {
		require.NotNil(t, e.To4(), "upstream_dns currently only stores IPv4; got %v", e)
	}
}

func TestBuildRulesetEmptyUpstreamDNS(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{UpstreamDNS: nil, FirewallUID: 100})
	require.Empty(t, rs.Sets["upstream_dns"].Elements)
}
