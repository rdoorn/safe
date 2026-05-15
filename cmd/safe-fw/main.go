// Package main is the entrypoint for the nftables seeder (safe-fw).
//
// safe-fw runs once at container init, reads /etc/safe/config.yaml,
// renders the SAFE base ruleset, and applies it via `nft -f -`. After
// that it exits; safe-dns owns ongoing rule manipulation.
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/firewall"
)

const (
	defaultConfigPath  = "/etc/safe/config.yaml"
	defaultFirewallUID = 100
	applyTimeout       = 10 * time.Second
)

func main() {
	var (
		configPath  = flag.String("config", defaultConfigPath, "path to safe config")
		firewallUID = flag.Uint("firewall-uid", defaultFirewallUID, "uid of the firewall user (owns safe-dns)")
		nftPath     = flag.String("nft", firewall.DefaultNFTPath(), "path to the nft binary")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	uid := *firewallUID
	if uid > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "safe-fw: --firewall-uid %d exceeds uint32 max\n", uid)
		os.Exit(1)
	}
	if err := run(ctx, *configPath, uint32(uid), *nftPath); err != nil {
		fmt.Fprintln(os.Stderr, "safe-fw:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, firewallUID uint32, nftPath string) error {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", configPath, err)
	}

	upstream := make([]net.IP, 0, len(cfg.UpstreamDNS))
	for _, s := range cfg.UpstreamDNS {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("upstream_dns: %q is not a valid IP", s)
		}
		upstream = append(upstream, ip)
	}
	if len(upstream) == 0 {
		return fmt.Errorf("upstream_dns: at least one resolver required")
	}

	rs := firewall.Build(firewall.Inputs{UpstreamDNS: upstream, FirewallUID: firewallUID})
	return firewall.Apply(ctx, rs, firewall.ApplyOptions{NFTPath: nftPath})
}
