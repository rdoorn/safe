package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunInitWritesUnderDotSafe(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	body, err := os.ReadFile(filepath.Join(cwd, ".safe", "safe.yaml")) //nolint:gosec
	require.NoError(t, err)
	require.Contains(t, string(body), "upstream_dns:")
}

func TestRunInitCreatesGitignoreWithDotSafeWhenAbsent(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	gi, err := os.ReadFile(filepath.Join(cwd, ".gitignore")) //nolint:gosec
	require.NoError(t, err)
	require.Contains(t, string(gi), ".safe/")
}

func TestRunInitAppendsToExistingGitignoreIdempotently(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, ".gitignore"), []byte("node_modules/\n"), 0o600))
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	gi, _ := os.ReadFile(filepath.Join(cwd, ".gitignore")) //nolint:gosec
	s := string(gi)
	require.Contains(t, s, "node_modules/")
	require.Contains(t, s, ".safe/")

	// Idempotent: second call (with --force so the safe.yaml write doesn't error)
	// must not double the .safe/ entry.
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, true))
	gi2, _ := os.ReadFile(filepath.Join(cwd, ".gitignore")) //nolint:gosec
	require.Equal(t, 1, bytes.Count(gi2, []byte(".safe/")),
		"ignore entry must be added exactly once")
}

func TestRunInitDoesNotCreateDockerignoreWhenAbsent(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	_, err := os.Stat(filepath.Join(cwd, ".dockerignore"))
	require.ErrorIs(t, err, os.ErrNotExist, "must NOT create .dockerignore when absent")
}

func TestRunInitUpdatesDockerignoreWhenPresent(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, ".dockerignore"), []byte("dist/\n"), 0o600))
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	di, _ := os.ReadFile(filepath.Join(cwd, ".dockerignore")) //nolint:gosec
	require.Contains(t, string(di), "dist/")
	require.Contains(t, string(di), ".safe/")
}

func TestRunInitUpdatesOtherExistingIgnoreFiles(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, ".eslintignore"), []byte("build/\n"), 0o600))
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	di, _ := os.ReadFile(filepath.Join(cwd, ".eslintignore")) //nolint:gosec
	require.Contains(t, string(di), ".safe/")
}

func TestRunInitDoesNotCreateOtherIgnoreFiles(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))
	for _, n := range []string{".dockerignore", ".eslintignore", ".prettierignore", ".npmignore"} {
		_, err := os.Stat(filepath.Join(cwd, n))
		require.ErrorIs(t, err, os.ErrNotExist, "must NOT create %s", n)
	}
}

func TestRunInitRefusesToOverwriteSafeYamlWithoutForce(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))
	err := runInit(&bytes.Buffer{}, cwd, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
