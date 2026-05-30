//go:build !linux

package resolver

import "errors"

// errUnsupportedPlatform is returned by applyToKernel on non-Linux hosts
// where netlink/nftables is not available. SetUpdater is only meant to
// run inside the SAFE container (Linux); non-Linux compilation exists
// only so the package builds on macOS for development.
var errUnsupportedPlatform = errors.New("nftables set updates require Linux")

// applyToKernel on non-Linux is a stub: SetUpdater cannot talk to
// nftables off Linux. safe-dns refuses to run anywhere but Linux in
// practice; this exists only so the package compiles on macOS for
// development.
func (u *SetUpdater) applyToKernel(_ ipBatch) error {
	return errUnsupportedPlatform
}
