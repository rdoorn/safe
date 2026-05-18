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
	// MkdirTemp creates at 0o700; widen to 0o755 so non-root uids in the
	// container can traverse to read config.yaml.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // 0o755 is intentional; non-root uids inside the container must traverse
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, configYAML, 0o644); err != nil { //nolint:gosec // public config, no secrets
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile's mode is ANDed with the caller's umask; chmod explicitly
	// so a strict umask (e.g. 0o077) doesn't leave the file at 0o600 and
	// block the firewall/keyholder uids inside the container from reading it.
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // public config, no secrets; must be world-readable for container uids
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("chmod %s: %w", path, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}
