package dockerrun

import (
	"fmt"
	"os"
	"path/filepath"
)

// NewConfigDir creates a fresh 0755 directory under the system temp root
// with the given prefix, writes the YAML payload to config.yaml at mode
// 0644 inside it, and returns the directory path plus a cleanup func.
//
// The file holds no secrets (resolvers, allowlist, agent metadata only),
// so it is intentionally world-readable inside the container — firewall,
// keyholder, and agent uids all need to read their slice of it.
func NewConfigDir(prefix string, configYAML []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", func() {}, fmt.Errorf("mktemp: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, configYAML, 0o644); err != nil { //nolint:gosec // public config, no secrets
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("write %s: %w", path, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}
