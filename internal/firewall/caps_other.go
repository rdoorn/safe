//go:build !linux

package firewall

import "errors"

// EnableAmbientCapNetAdmin is a no-op stub on non-Linux platforms.
// safe-dns refuses to start anywhere but Linux in practice, so this
// path only exists so the package compiles cleanly on macOS for
// development and unit testing.
func EnableAmbientCapNetAdmin() error {
	return errors.New("ambient caps not supported on this platform")
}
