//go:build !linux

package initd

import "errors"

// ErrUnsupportedPlatform is returned by Linux-only initd functions when
// the binary is built for a non-Linux GOOS.
var ErrUnsupportedPlatform = errors.New("safe-init: requires Linux")

func dropPrivileges(_, _ uint32) error { return ErrUnsupportedPlatform }
