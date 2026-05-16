package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitWritesDefaultConfig(t *testing.T) {
	dir := t.TempDir()

	var out bytes.Buffer
	require.NoError(t, runInit(&out, dir, false))

	path := filepath.Join(dir, "safe.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // test-only fixture path
	require.NoError(t, err)
	require.Contains(t, string(data), "agents:")
	require.Contains(t, string(data), "claude:")
	require.Contains(t, string(data), "api.anthropic.com")
	require.Contains(t, out.String(), path)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestInitRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "safe.yaml")
	require.NoError(t, os.WriteFile(target, []byte("hand-written"), 0o600))

	err := runInit(&bytes.Buffer{}, dir, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	data, _ := os.ReadFile(target) //nolint:gosec // test-only fixture path
	require.Equal(t, "hand-written", string(data), "existing config preserved")
}

func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "safe.yaml")
	require.NoError(t, os.WriteFile(target, []byte("hand-written"), 0o600))

	require.NoError(t, runInit(&bytes.Buffer{}, dir, true))

	data, _ := os.ReadFile(target) //nolint:gosec // test-only fixture path
	require.Contains(t, string(data), "agents:", "template was written")
	require.NotContains(t, string(data), "hand-written")
}
