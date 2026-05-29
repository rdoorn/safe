package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitRTKCallsBinary(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")

	// Fake rtk binary: records its argv then exits 0.
	fakeBin := filepath.Join(dir, "rtk")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\n"
	require.NoError(t, os.WriteFile(fakeBin, []byte(script), 0o755)) //nolint:gosec // test helper script must be executable

	initRTK(fakeBin)

	got, err := os.ReadFile(argsFile) //nolint:gosec // path is test-controlled
	require.NoError(t, err, "fake rtk binary was not called")
	// --auto-patch is required: startup is non-interactive, so without it the
	// settings.json prompt defaults to N and the hook is never installed.
	require.Equal(t, "init -g --auto-patch", strings.TrimSpace(string(got)))
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
