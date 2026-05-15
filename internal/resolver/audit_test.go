package resolver_test

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

func TestAuditAllow(t *testing.T) {
	var buf bytes.Buffer
	a := resolver.NewJSONLAuditor(&buf)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	a.Allow("api.anthropic.com.", addr, []net.IP{net.ParseIP("1.2.3.4")}, 5*time.Minute)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "allow", got["event"])
	require.Equal(t, "api.anthropic.com.", got["fqdn"])
	require.Equal(t, (5 * time.Minute).String(), got["ttl"])
	require.Equal(t, []any{"1.2.3.4"}, got["ips"])
}

func TestAuditDeny(t *testing.T) {
	var buf bytes.Buffer
	a := resolver.NewJSONLAuditor(&buf)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	a.Deny("evil.com.", addr)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "deny", got["event"])
	require.Equal(t, "evil.com.", got["fqdn"])
	require.NotContains(t, got, "ttl")
}

func TestAuditNilWriterNoOp(t *testing.T) {
	// Nil auditor in the server is allowed; an auditor with a nil writer
	// should also no-op rather than panic.
	a := resolver.NewJSONLAuditor(nil)
	require.NotPanics(t, func() {
		a.Allow("x.", nil, []net.IP{net.ParseIP("1.2.3.4")}, time.Second)
		a.Deny("y.", nil)
	})
}
