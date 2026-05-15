package dockerrun_test

import (
	"os"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestNewSocketDirCreatesAndCleans(t *testing.T) {
	path, cleanup, err := dockerrun.NewSocketDir("safe-")
	require.NoError(t, err)
	t.Cleanup(cleanup)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	cleanup()
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err), "cleanup removed the dir")
}

func TestNewSocketDirUniquePerCall(t *testing.T) {
	a, ca, err := dockerrun.NewSocketDir("safe-")
	require.NoError(t, err)
	defer ca()
	b, cb, err := dockerrun.NewSocketDir("safe-")
	require.NoError(t, err)
	defer cb()
	require.NotEqual(t, a, b)
}
