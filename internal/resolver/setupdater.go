package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rdoorn/safe/internal/firewall"
)

// SetUpdater installs entries into the inet safe.allowed_v4 / allowed_v6
// dynamic sets so the kernel accepts outbound traffic to a host the
// agent just resolved through us.
type SetUpdater struct {
	// NFTPath is the absolute path to the nft binary. Empty falls back
	// to firewall.DefaultNFTPath().
	NFTPath string
	// Runner is swappable for tests. Nil falls back to firewall.ExecRunner.
	Runner firewall.Runner
}

// Add inserts a single IP into the appropriate set with the given timeout.
// Whole-second resolution; sub-second ttls are rounded up to 1s.
func (u *SetUpdater) Add(ctx context.Context, ip net.IP, ttl time.Duration) error {
	return u.AddMany(ctx, []net.IP{ip}, ttl)
}

// AddMany inserts a batch in a single nft transaction.
func (u *SetUpdater) AddMany(ctx context.Context, ips []net.IP, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}

	var sb strings.Builder
	for _, ip := range ips {
		if ip == nil {
			return errors.New("nil IP")
		}
		setName := "allowed_v4"
		canonical := ip.String()
		if v4 := ip.To4(); v4 != nil {
			canonical = v4.String()
		} else {
			setName = "allowed_v6"
		}
		fmt.Fprintf(&sb, "add element inet safe %s { %s timeout %s }\n", setName, canonical, formatTTL(ttl))
	}

	nftPath := u.NFTPath
	if nftPath == "" {
		nftPath = firewall.DefaultNFTPath()
	}
	r := u.Runner
	if r == nil {
		r = firewall.ExecRunner{}
	}

	_, stderr, err := r.Run(ctx, nftPath, []string{"-f", "-"}, sb.String())
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft set add: %s", msg)
	}
	return nil
}

// formatTTL renders a duration as nft expects: integer seconds with a
// trailing "s". Sub-second durations round up to 1s.
func formatTTL(d time.Duration) string {
	if d < time.Second {
		d = time.Second
	}
	return fmt.Sprintf("%ds", int64(d.Seconds()))
}
