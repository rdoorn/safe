package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitRTKCallsBinary(t *testing.T) {
	dir := t.TempDir()
	flagFile := filepath.Join(dir, "ran")

	// Fake rtk binary: writes a flag file then exits 0.
	fakeBin := filepath.Join(dir, "rtk")
	script := "#!/bin/sh\ntouch " + flagFile + "\n"
	require.NoError(t, os.WriteFile(fakeBin, []byte(script), 0o755)) //nolint:gosec // test helper script must be executable

	initRTK(fakeBin)

	_, err := os.Stat(flagFile)
	require.NoError(t, err, "fake rtk binary was not called")
}

func TestInitRTKNonZeroExitDoesNotPanic(t *testing.T) {
	dir := t.TempDir()

	// Fake rtk binary that fails.
	fakeBin := filepath.Join(dir, "rtk")
	require.NoError(t, os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 1\n"), 0o755)) //nolint:gosec // test helper script must be executable

	// Should not panic or call t.Fatal.
	initRTK(fakeBin)
}

func TestInitRTKMissingBinaryDoesNotPanic(_ *testing.T) {
	initRTK("/nonexistent/rtk")
}
