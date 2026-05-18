package dockerrun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestNewConfigDirWritesYAML(t *testing.T) {
	dir, cleanup, err := dockerrun.NewConfigDir("safe-cfg-", []byte("upstream_dns:\n  - 1.1.1.1\n"))
	require.NoError(t, err)
	defer cleanup()

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	body, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, "upstream_dns:\n  - 1.1.1.1\n", string(body))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}

func TestNewConfigDirCleanupRemovesEverything(t *testing.T) {
	dir, cleanup, err := dockerrun.NewConfigDir("safe-cfg-", []byte("x: y\n"))
	require.NoError(t, err)
	cleanup()

	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}
