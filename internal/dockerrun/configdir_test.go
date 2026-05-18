package dockerrun_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestWriteConfigDir(t *testing.T) {
	dir := t.TempDir()
	err := dockerrun.WriteConfigDir(dir, []byte("upstream_dns:\n  - 1.1.1.1\n"))
	require.NoError(t, err)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	body, err := os.ReadFile(filepath.Join(dir, "config.yaml")) //nolint:gosec // path under test control
	require.NoError(t, err)
	require.Equal(t, "upstream_dns:\n  - 1.1.1.1\n", string(body))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}

func TestWriteConfigDirOverridesRestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	dir := t.TempDir()
	require.NoError(t, dockerrun.WriteConfigDir(dir, []byte("x: y\n")))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm(),
		"file mode must be 0o644 regardless of caller umask")
}
