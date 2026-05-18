package dockerrun_test

import (
	"os"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestPrepareSocketDirSets0700(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, dockerrun.PrepareSocketDir(dir))

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}
