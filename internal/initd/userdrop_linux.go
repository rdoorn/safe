//go:build linux

package initd

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func dropPrivileges(uid, gid uint32) error {
	// Order matters: groups before uid (must still be privileged to setgroups),
	// then gid, then uid. After setuid we are unprivileged.
	if err := unix.Setgroups([]int{int(gid)}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(gid)); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	return nil
}
