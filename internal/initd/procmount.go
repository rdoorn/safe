package initd

// RemountProcHidepid bind-remounts /proc with hidepid=2 so non-firewall
// users cannot see other users' processes via /proc/<pid>. This is the
// critical kernel-side guard that keeps the agent uid from inspecting
// keyholder's environ/maps/mem.
//
// firewallGID is the gid permitted to see all entries (used by safe-dns
// for diagnostics).
func RemountProcHidepid(firewallGID uint32) error {
	return remountProcHidepid(firewallGID)
}
