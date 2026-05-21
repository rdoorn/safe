//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// hardenAgentSubtree applies two defense-in-depth measures that take
// effect for safe-init's NEXT fork+exec — i.e. the agent process —
// and are inherited across all of its descendants:
//
//  1. PR_SET_NO_NEW_PRIVS = 1. The agent (and any binary it execs) can
//     never gain new privileges via file caps or setuid bits.
//  2. PR_CAPBSET_DROP for the caps SAFE granted to the container as a
//     whole. The agent's bounding set is empty for these, so it can
//     never acquire CAP_NET_ADMIN/SETUID/SETGID/KILL/CHOWN even if
//     someone (e.g. an attacker who somehow forced safe-init to exec a
//     file-cap'd binary) tried.
//
// safe-dns and safe-keyholder are already running with their needed
// caps; bounding-set changes on the parent (safe-init) don't retract
// caps from already-exec'd children. So this is a clean tightening
// targeted at the agent subtree only.
//
// no-new-privs is NOT applied at container level via
// `--security-opt no-new-privileges` because that would also break
// safe-dns's file-cap (kernel ignores file caps under no_new_privs).
// Applying it after safe-dns is already running sidesteps that.
func hardenAgentSubtree() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	for _, cap := range []uintptr{
		unix.CAP_NET_ADMIN,
		unix.CAP_SETUID,
		unix.CAP_SETGID,
		unix.CAP_KILL,
		unix.CAP_CHOWN,
		unix.CAP_SYS_ADMIN, // also drop optional extras the agent doesn't need
		unix.CAP_SYS_PTRACE,
		unix.CAP_NET_BIND_SERVICE,
	} {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0); err != nil {
			return fmt.Errorf("PR_CAPBSET_DROP cap=%d: %w", cap, err)
		}
	}
	return nil
}
