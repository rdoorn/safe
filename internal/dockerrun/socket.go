package dockerrun

import (
	"fmt"
	"os"
)

// PrepareSocketDir assumes dir exists; sets it to 0700 so only the host
// user (and root inside the container, which creates the socket) can
// traverse to safe-keyholder's bootstrap socket.
func PrepareSocketDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0o700 is the intended secure mode for the socket dir
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}
