// Package main is the entrypoint for the FQDN-allowlist DNS resolver (safe-dns).
//
// safe-dns runs as user `firewall` inside the SAFE container. It listens
// on 127.0.0.1:53, allowlists DNS queries against the SAFE config, forwards
// allowed queries to an upstream resolver, and installs nftables rules so
// the resolved IPs become temporarily reachable from the agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/firewall"
	"github.com/rdoorn/safe/internal/resolver"
)

const (
	defaultConfigPath  = "/etc/safe/config.yaml"
	defaultListenAddr  = "127.0.0.1:53"
	defaultAuditPath   = "/var/log/safe/audit.log"
	defaultExchangeTTL = 5 * time.Second
)

func main() {
	var (
		configPath = flag.String("config", defaultConfigPath, "path to safe config")
		listenAddr = flag.String("listen", defaultListenAddr, "listen address (udp+tcp)")
		auditPath  = flag.String("audit", defaultAuditPath, "audit log path (jsonl)")
		nftPath    = flag.String("nft", firewall.DefaultNFTPath(), "path to nft binary")
		minTTL     = flag.Duration("min-ttl", resolver.DefaultMinTTL, "minimum allow rule lifetime")
		maxTTL     = flag.Duration("max-ttl", resolver.DefaultMaxTTL, "maximum allow rule lifetime")
	)
	flag.Parse()

	if *minTTL <= 0 || *maxTTL <= 0 || *minTTL > *maxTTL {
		fmt.Fprintln(os.Stderr, "safe-dns: invalid TTL bounds")
		os.Exit(1)
	}

	if err := run(*configPath, *listenAddr, *auditPath, *nftPath, *minTTL, *maxTTL); err != nil {
		fmt.Fprintln(os.Stderr, "safe-dns:", err)
		os.Exit(1)
	}
}

func run(configPath, listenAddr, auditPath, nftPath string, minTTL, maxTTL time.Duration) error {
	// Raise ambient CAP_NET_ADMIN so the nft processes we fork inherit it.
	// File capabilities don't propagate across exec into a binary that
	// has none of its own, so without this nft would always fail.
	if err := firewall.EnableAmbientCapNetAdmin(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-dns: cannot raise ambient CAP_NET_ADMIN:", err)
		fmt.Fprintln(os.Stderr, "safe-dns: nft set updates will fail; continuing for diagnostics")
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if len(cfg.UpstreamDNS) == 0 {
		return fmt.Errorf("upstream_dns: at least one resolver required")
	}

	upstreams := make([]string, 0, len(cfg.UpstreamDNS))
	for _, u := range cfg.UpstreamDNS {
		if net.ParseIP(u) == nil {
			return fmt.Errorf("upstream_dns: %q is not an IP", u)
		}
		upstreams = append(upstreams, net.JoinHostPort(u, "53"))
	}

	auditFile, err := openAudit(auditPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() {
		if auditFile != nil {
			_ = auditFile.Close()
		}
	}()

	srv := &resolver.Server{
		Matcher:  resolver.NewMatcher(cfg.Allowlist),
		Upstream: newDNSClientUpstream(upstreams, defaultExchangeTTL),
		Updater:  &resolver.SetUpdater{NFTPath: nftPath},
		Audit:    resolver.NewJSONLAuditor(auditFile),
		ErrorLog: os.Stderr,
		MinTTL:   minTTL,
		MaxTTL:   maxTTL,
	}

	addr, err := srv.Start(listenAddr)
	if err != nil {
		return fmt.Errorf("start dns server: %w", err)
	}
	fmt.Fprintln(os.Stderr, "safe-dns: listening on", addr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	srv.Close()
	return nil
}

func openAudit(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	const perm = 0o600
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, perm) //nolint:gosec // path is admin-set via config
}

// dnsClientUpstream is a tiny miekg/dns wrapper that rotates over the
// configured resolvers.
type dnsClientUpstream struct {
	resolvers []string
	client    *dns.Client
}

func newDNSClientUpstream(addrs []string, timeout time.Duration) *dnsClientUpstream {
	c := new(dns.Client)
	c.Timeout = timeout
	return &dnsClientUpstream{resolvers: addrs, client: c}
}

func (u *dnsClientUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	deadline, ok := ctx.Deadline()
	c := u.client
	if ok {
		// Shorten our client timeout if the caller passed a tighter deadline.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("context deadline exceeded")
		}
		if remaining < u.client.Timeout {
			c = &dns.Client{Net: u.client.Net, Timeout: remaining}
		}
	}
	var lastErr error
	for _, r := range u.resolvers {
		resp, _, err := c.Exchange(msg, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream resolvers configured")
	}
	return nil, lastErr
}
