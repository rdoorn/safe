//go:build !linux

package initd

func remountProcHidepid(_ uint32) error { return ErrUnsupportedPlatform }
