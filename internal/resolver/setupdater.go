package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// SetUpdater installs entries into the inet safe.allowed_v4 / allowed_v6
// dynamic sets so the kernel accepts outbound traffic to a host the
// agent just resolved through us.
//
// It uses netlink directly (via google/nftables) rather than fork+exec'ing
// the nft CLI. The reason is Linux capability semantics: ambient
// capabilities are per-thread, and Go's runtime schedules goroutines
// across multiple OS threads — so the thread doing fork+exec usually
// doesn't have ambient cap_net_admin even if the main thread does. With
// netlink we stay in-process; cap_net_admin is in the effective set on
// every thread (inherited at thread clone), so netlink calls succeed
// from any goroutine.
type SetUpdater struct {
	// TableName defaults to "safe".
	TableName string
	// SetNameV4 / SetNameV6 default to "allowed_v4" / "allowed_v6".
	SetNameV4 string
	SetNameV6 string

	// NFTPath and Runner are retained for backwards compatibility with
	// v1 wiring (cmd/safe-dns and tests). They are no longer used at
	// runtime now that updates go via netlink.
	NFTPath string
	Runner  any
}

// IPBatch is the set-elements split into v4 and v6 by Add/AddMany. It is
// exposed so the platform-specific netlink path can consume it.
type ipBatch struct {
	v4  []net.IP
	v6  []net.IP
	ttl time.Duration
}

// Add inserts a single IP into the appropriate set with the given timeout.
func (u *SetUpdater) Add(ctx context.Context, ip net.IP, ttl time.Duration) error {
	return u.AddMany(ctx, []net.IP{ip}, ttl)
}

// AddMany inserts a batch in a single netlink transaction.
func (u *SetUpdater) AddMany(_ context.Context, ips []net.IP, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	u.applyDefaults()

	batch := ipBatch{ttl: roundUpToSeconds(ttl)}
	for _, ip := range ips {
		if ip == nil {
			return errors.New("nil IP")
		}
		if v4 := ip.To4(); v4 != nil {
			batch.v4 = append(batch.v4, v4)
		} else {
			batch.v6 = append(batch.v6, ip.To16())
		}
	}

	return u.applyToKernel(batch)
}

func (u *SetUpdater) applyDefaults() {
	if u.TableName == "" {
		u.TableName = "safe"
	}
	if u.SetNameV4 == "" {
		u.SetNameV4 = "allowed_v4"
	}
	if u.SetNameV6 == "" {
		u.SetNameV6 = "allowed_v6"
	}
}

// roundUpToSeconds rounds d up to the next whole second, with a minimum
// of one second. nftables timeouts have second granularity.
func roundUpToSeconds(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	if d%time.Second == 0 {
		return d
	}
	return (d/time.Second + 1) * time.Second
}

// Compile-time guard that ipBatch is used; silences unused-warnings on
// non-Linux builds where applyToKernel ignores it.
var _ = ipBatch{}
var _ = fmt.Sprintf
