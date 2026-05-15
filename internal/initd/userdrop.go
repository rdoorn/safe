package initd

// DropPrivileges drops effective uid/gid to the supplied values, clears
// supplementary groups, and sets PR_SET_NO_NEW_PRIVS so subsequent execs
// cannot gain additional privileges (no setuid binaries can elevate).
//
// Implementations are in userdrop_linux.go (real syscalls) and
// userdrop_other.go (returns ErrUnsupportedPlatform). safe-init refuses
// to start anywhere but Linux because everything else in this package
// assumes a Linux kernel namespace.
func DropPrivileges(uid, gid uint32) error {
	return dropPrivileges(uid, gid)
}
