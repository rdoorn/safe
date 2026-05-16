//go:build !linux

package resolver

// applyToKernel on non-Linux is a stub: SetUpdater cannot talk to
// nftables off Linux. safe-dns refuses to run anywhere but Linux in
// practice; this exists only so the package compiles on macOS for
// development.
func (u *SetUpdater) applyToKernel(_ ipBatch) error {
	return errUnsupportedPlatform
}
