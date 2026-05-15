//go:build linux

package initd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func remountProcHidepid(firewallGID uint32) error {
	opts := fmt.Sprintf("hidepid=2,gid=%d", firewallGID)
	// MS_REMOUNT requires the source to match the original ("proc") and
	// the target to be the existing mountpoint.
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_REMOUNT, opts); err != nil {
		return fmt.Errorf("remount /proc with %s: %w", opts, err)
	}
	return nil
}
