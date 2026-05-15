package resolver_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

// stubUpstream returns canned answers from a fixed table keyed by lowercase
// FQDN.
type stubUpstream struct {
	answers map[string][]net.IP
}

func (s *stubUpstream) Exchange(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(msg)
	if len(msg.Question) == 0 {
		return resp, nil
	}
	q := msg.Question[0]
	name := q.Name
	ips, ok := s.answers[name]
	if !ok {
		resp.Rcode = dns.RcodeNameError
		return resp, nil
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   v4,
			})
		} else {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ip,
			})
		}
	}
	return resp, nil
}

type stubSetUpdater struct {
	added map[string]time.Duration
}

func newStubSetUpdater() *stubSetUpdater { return &stubSetUpdater{added: map[string]time.Duration{}} }

func (s *stubSetUpdater) AddMany(_ context.Context, ips []net.IP, ttl time.Duration) error {
	for _, ip := range ips {
		s.added[ip.String()] = ttl
	}
	return nil
}

func startTestServer(t *testing.T, srv *resolver.Server) string {
	t.Helper()
	addr, err := srv.Start("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { srv.Close() })
	return addr
}

func TestServerForwardsAllowed(t *testing.T) {
	updater := newStubSetUpdater()
	srv := &resolver.Server{
		Matcher:  resolver.NewMatcher([]string{"api.anthropic.com"}),
		Upstream: &stubUpstream{answers: map[string][]net.IP{"api.anthropic.com.": {net.ParseIP("1.2.3.4")}}},
		Updater:  updater,
		MinTTL:   30 * time.Second,
		MaxTTL:   time.Hour,
	}
	addr := startTestServer(t, srv)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("api.anthropic.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
	require.Contains(t, updater.added, "1.2.3.4")
	require.Equal(t, 300*time.Second, updater.added["1.2.3.4"])
}

func TestServerDeniesUnknownName(t *testing.T) {
	updater := newStubSetUpdater()
	upstreamCalls := 0
	upstream := &stubUpstream{answers: map[string][]net.IP{}}
	srv := &resolver.Server{
		Matcher:  resolver.NewMatcher([]string{"api.anthropic.com"}),
		Upstream: countingUpstream{u: upstream, calls: &upstreamCalls},
		Updater:  updater,
		MinTTL:   30 * time.Second,
		MaxTTL:   time.Hour,
	}
	addr := startTestServer(t, srv)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("evil.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeNameError, resp.Rcode, "deny returns NXDOMAIN")
	require.Equal(t, 0, upstreamCalls, "denied name must not be forwarded upstream")
	require.Empty(t, updater.added, "no allow rule installed for denied name")
}

type countingUpstream struct {
	u     resolver.Upstream
	calls *int
}

func (c countingUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	*c.calls++
	return c.u.Exchange(ctx, m)
}

func TestServerClampsTTL(t *testing.T) {
	updater := newStubSetUpdater()
	srv := &resolver.Server{
		Matcher:  resolver.NewMatcher([]string{"slow.example.com"}),
		Upstream: &stubUpstream{answers: map[string][]net.IP{"slow.example.com.": {net.ParseIP("9.9.9.9")}}},
		Updater:  updater,
		MinTTL:   30 * time.Second,
		MaxTTL:   60 * time.Second, // tight clamp
	}
	addr := startTestServer(t, srv)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("slow.example.com.", dns.TypeA)
	_, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	require.Equal(t, 60*time.Second, updater.added["9.9.9.9"], "TTL clamp to MaxTTL")
}
