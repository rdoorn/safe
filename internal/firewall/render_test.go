package firewall_test

import (
	"net"
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/firewall"
	"github.com/stretchr/testify/require"
)

func TestRenderHasTableAndChainPolicy(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 200,
	})
	out := firewall.Render(rs)
	require.Contains(t, out, "table inet safe {")
	require.Contains(t, out, "type filter hook output priority filter")
	require.Contains(t, out, "policy drop")
}

func TestRenderHasDynamicSetsWithTimeout(t *testing.T) {
	out := firewall.Render(firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 200,
	}))
	require.Contains(t, out, "set allowed_v4 {")
	require.Contains(t, out, "type ipv4_addr")
	require.Contains(t, out, "flags timeout, dynamic")

	require.Contains(t, out, "set allowed_v6 {")
	require.Contains(t, out, "type ipv6_addr")
}

func TestRenderHasUpstreamDNSSetWithElements(t *testing.T) {
	out := firewall.Render(firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")},
		FirewallUID: 200,
	}))
	require.Contains(t, out, "set upstream_dns {")
	require.Contains(t, out, "elements = { 1.1.1.1, 1.0.0.1 }")
}

func TestRenderRulesInOrder(t *testing.T) {
	out := firewall.Render(firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 200,
	}))
	// Order matters: nftables is first-match-wins inside a chain when an
	// accept verdict short-circuits. We rely on the established/related
	// rule being first to keep CPU cost low.
	idxEst := strings.Index(out, "ct state established,related accept")
	idxLo := strings.Index(out, "oif \"lo\" accept")
	idxLocalDNS := strings.Index(out, "udp dport 53 ip daddr 127.0.0.1 accept")
	idxUpstreamDNS := strings.Index(out, "meta skuid 200 udp dport 53 ip daddr @upstream_dns accept")
	idxAllowedV4 := strings.Index(out, "ip daddr @allowed_v4 accept")
	idxAllowedV6 := strings.Index(out, "ip6 daddr @allowed_v6 accept")

	for _, idx := range []int{idxEst, idxLo, idxLocalDNS, idxUpstreamDNS, idxAllowedV4, idxAllowedV6} {
		require.NotEqual(t, -1, idx, "missing rule in output:\n%s", out)
	}
	require.Less(t, idxEst, idxLo)
	require.Less(t, idxLo, idxLocalDNS)
	require.Less(t, idxLocalDNS, idxUpstreamDNS)
	require.Less(t, idxUpstreamDNS, idxAllowedV4)
	require.Less(t, idxAllowedV4, idxAllowedV6)
}

func TestRenderIsDeterministic(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")},
		FirewallUID: 200,
	})
	a := firewall.Render(rs)
	b := firewall.Render(rs)
	require.Equal(t, a, b)
}
