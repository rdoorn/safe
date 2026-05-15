package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintConfigMergedYAML(t *testing.T) {
	xdg := t.TempDir()
	cwd := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(xdg, "safe"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(xdg, "safe", "safe.yaml"),
		[]byte("allowlist:\n  - global.example.com\n"),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(cwd, "safe.yaml"),
		[]byte("allowlist:\n  - project.example.com\n"),
		0o600,
	))

	var buf bytes.Buffer
	require.NoError(t, printConfig(&buf, xdg, cwd))
	out := buf.String()
	require.Contains(t, out, "global.example.com")
	require.Contains(t, out, "project.example.com")
}

func TestPrintConfigNoFiles(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printConfig(&buf, t.TempDir(), t.TempDir()))
	// Should emit *some* YAML (the empty merged config), without error.
	require.NotEmpty(t, buf.String())
}
