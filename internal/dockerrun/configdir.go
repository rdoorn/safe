package dockerrun

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteConfigDir assumes dir exists; widens it to 0755 and writes
// config.yaml inside at mode 0644. Mode is set defensively (Chmod after
// WriteFile) so a strict caller umask cannot downgrade it — firewall,
// keyholder, and agent uids inside the container all need to read the
// file, which holds no secrets (resolvers, allowlist, agent metadata).
func WriteConfigDir(dir string, configYAML []byte) error {
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // 0o755 is intentional; non-root container uids must traverse
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, configYAML, 0o644); err != nil { //nolint:gosec // public config, must be world-readable in-container
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // see above
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
