//go:build linux

package firewall

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// capNetAdmin is CAP_NET_ADMIN from <linux/capability.h>. It lives in
// the first u32 of the capability bitmask (CAP_TO_INDEX(12) == 0).
const capNetAdmin = 12

// EnableAmbientCapNetAdmin raises CAP_NET_ADMIN in the calling process's
// ambient capability set so that exec'd children — notably nft — inherit
// the capability via the ambient->permitted/effective transition. The
// process must already have CAP_NET_ADMIN in its permitted set (typically
// via file capabilities on /usr/sbin/safe-dns).
//
// Why this exists: file capabilities are NOT propagated across exec
// into a binary that has no file caps of its own. safe-dns has the cap;
// the nft binary it forks does not. Without ambient caps, nft starts
// with zero capabilities and fails with "Operation not permitted".
func EnableAmbientCapNetAdmin() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	capBit := uint32(1) << capNetAdmin
	if data[0].Permitted&capBit == 0 {
		return fmt.Errorf("CAP_NET_ADMIN is not in the permitted set; ensure file caps on safe-dns and that --security-opt no-new-privileges is NOT set on the container")
	}

	// To raise ambient, the cap must be in both inheritable and permitted.
	data[0].Inheritable |= capBit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset (add inheritable): %w", err)
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, capNetAdmin, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_CAP_AMBIENT_RAISE CAP_NET_ADMIN: %w", err)
	}
	return nil
}
