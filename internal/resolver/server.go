package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream is the abstraction over the real DNS resolver SAFE forwards
// allowed queries to (Cloudflare 1.1.1.1 in production).
type Upstream interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

// AllowSetUpdater pushes resolved IPs into the kernel allow set so the
// caller can actually connect. The full SetUpdater satisfies this; tests
// can pass a stub.
type AllowSetUpdater interface {
	AddMany(ctx context.Context, ips []net.IP, ttl time.Duration) error
}

// Auditor records allow/deny events for human-readable post-mortems.
// Nil is safe (no-op).
type Auditor interface {
	Allow(name string, clientAddr net.Addr, ips []net.IP, ttl time.Duration)
	Deny(name string, clientAddr net.Addr)
}

// Server is the SAFE FQDN-allowlist DNS resolver.
type Server struct {
	Matcher  *Matcher
	Upstream Upstream
	Updater  AllowSetUpdater
	Audit    Auditor
	MinTTL   time.Duration
	MaxTTL   time.Duration

	// ErrorLog, if non-nil, receives one-line messages for non-fatal
	// runtime errors that would otherwise be swallowed (upstream lookup
	// failures, nftables set-update failures). Production wires this to
	// os.Stderr so SERVFAIL responses have a corresponding log line.
	ErrorLog io.Writer

	mu        sync.Mutex
	udpServer *dns.Server
	tcpServer *dns.Server
}

func (s *Server) logError(format string, args ...any) {
	if s.ErrorLog == nil {
		return
	}
	_, _ = fmt.Fprintf(s.ErrorLog, "safe-dns: "+format+"\n", args...)
}

// Start binds the configured listen address on both UDP and TCP and
// begins serving in background goroutines. It returns the actual
// listening address (useful when "127.0.0.1:0" is passed in tests).
func (s *Server) Start(addr string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpServer != nil {
		return "", errors.New("already started")
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", fmt.Errorf("listen udp: %w", err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		_ = pc.Close()
		return "", fmt.Errorf("listen tcp: %w", err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.handle(w, r)
	})
	s.udpServer = &dns.Server{PacketConn: pc, Handler: handler}
	s.tcpServer = &dns.Server{Listener: ln, Handler: handler}

	udpReady := make(chan struct{})
	s.udpServer.NotifyStartedFunc = func() { close(udpReady) }
	tcpReady := make(chan struct{})
	s.tcpServer.NotifyStartedFunc = func() { close(tcpReady) }

	go func() { _ = s.udpServer.ActivateAndServe() }()
	go func() { _ = s.tcpServer.ActivateAndServe() }()
	<-udpReady
	<-tcpReady

	return pc.LocalAddr().String(), nil
}

// Close shuts down both listeners. Idempotent.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpServer != nil {
		_ = s.udpServer.Shutdown()
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		_ = s.tcpServer.Shutdown()
		s.tcpServer = nil
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		_ = w.WriteMsg(refusedReply(r))
		return
	}
	q := r.Question[0]

	if !s.Matcher.Allows(q.Name) {
		if s.Audit != nil {
			s.Audit.Deny(q.Name, w.RemoteAddr())
		}
		_ = w.WriteMsg(nxdomainReply(r))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.Upstream.Exchange(ctx, r)
	if err != nil || resp == nil {
		s.logError("upstream exchange for %q: %v", q.Name, err)
		_ = w.WriteMsg(servFailReply(r))
		return
	}

	ips, minTTL := extractIPsAndTTL(resp)
	if len(ips) > 0 {
		ttl := ClampTTL(time.Duration(minTTL)*time.Second, s.MinTTL, s.MaxTTL)
		if err := s.Updater.AddMany(ctx, ips, ttl); err != nil {
			s.logError("nft set update for %q (%d ips): %v", q.Name, len(ips), err)
			_ = w.WriteMsg(servFailReply(r))
			return
		}
		if s.Audit != nil {
			s.Audit.Allow(q.Name, w.RemoteAddr(), ips, ttl)
		}
	}

	_ = w.WriteMsg(resp)
}

func extractIPsAndTTL(m *dns.Msg) ([]net.IP, uint32) {
	var ips []net.IP
	minTTL := uint32(0)
	for _, ans := range m.Answer {
		switch v := ans.(type) {
		case *dns.A:
			ips = append(ips, v.A)
			minTTL = minOrInit(minTTL, v.Hdr.Ttl)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
			minTTL = minOrInit(minTTL, v.Hdr.Ttl)
		}
	}
	return ips, minTTL
}

func minOrInit(cur, candidate uint32) uint32 {
	if cur == 0 || candidate < cur {
		return candidate
	}
	return cur
}

func refusedReply(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeRefused)
	return resp
}

func nxdomainReply(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeNameError)
	return resp
}

func servFailReply(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeServerFailure)
	return resp
}
