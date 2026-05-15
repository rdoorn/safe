package dockerrun

import (
	"fmt"
	"os"
)

// NewSocketDir creates a fresh per-run directory at mode 0700 under the
// system temp root with the given prefix. The returned cleanup function
// removes the directory and any contents; callers must call it when the
// container exits.
func NewSocketDir(prefix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", func() {}, fmt.Errorf("mktemp: %w", err)
	}
	// MkdirTemp creates with 0o700 by default; assert explicitly to
	// guard against future stdlib changes.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0o700 is intentionally restrictive; gosec wants <=0o600 for files but this is a directory
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("chmod %s: %w", dir, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}
