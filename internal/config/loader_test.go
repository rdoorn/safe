package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "safe.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
agents:
  claude:
    image: x
    entrypoint: claude
allowlist:
  - api.anthropic.com
`), 0o600))

	cfg, err := config.LoadFile(path)
	require.NoError(t, err)
	require.Equal(t, "claude", cfg.Agents["claude"].Entrypoint)
}

func TestLoadFileMissing(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.LoadFile(filepath.Join(dir, "does-not-exist.yaml"))
	require.NoError(t, err)
	require.NotNil(t, cfg) // missing file = empty config, not error
	require.Empty(t, cfg.Agents)
}

func TestLoadAllOrdering(t *testing.T) {
	xdg := t.TempDir()
	cwd := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(xdg, "safe"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(xdg, "safe", "safe.yaml"),
		[]byte("allowlist:\n  - global.example.com\n"), 0o600,
	))
	require.NoError(t, os.MkdirAll(filepath.Join(cwd, ".safe"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(cwd, ".safe", "safe.yaml"),
		[]byte("allowlist:\n  - project.example.com\n"), 0o600,
	))

	configs, err := config.LoadAll(xdg, cwd)
	require.NoError(t, err)
	require.Len(t, configs, 2)
	require.Equal(t, []string{"global.example.com"}, configs[0].Allowlist)
	require.Equal(t, []string{"project.example.com"}, configs[1].Allowlist)
}

func TestLoadAllOnlyGlobal(t *testing.T) {
	xdg := t.TempDir()
	cwd := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(xdg, "safe"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(xdg, "safe", "safe.yaml"),
		[]byte("allowlist:\n  - global.example.com\n"), 0o600,
	))

	configs, err := config.LoadAll(xdg, cwd)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	require.Equal(t, []string{"global.example.com"}, configs[0].Allowlist)
}

func TestLoadAllNeither(t *testing.T) {
	configs, err := config.LoadAll(t.TempDir(), t.TempDir())
	require.NoError(t, err)
	require.Empty(t, configs)
}
