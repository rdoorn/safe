package dockerrun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func TestExpandMountsMountsEnabledOnesOnly(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(filepath.Join(claudeDir, "skills"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(claudeDir, "commands"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(claudeDir, "hooks"), 0o700))
	writeFile(t, filepath.Join(claudeDir, "CLAUDE.md"), "# global\n")

	flags := dockerrun.ExpandMounts(claudeDir, config.Customization{
		Skills:   true,
		Commands: true,
		ClaudeMD: true,
		Hooks:    false,
	})

	joined := flagsAsString(flags)
	require.Contains(t, joined, filepath.Join(claudeDir, "skills")+":/home/agent/.claude/skills:ro")
	require.Contains(t, joined, filepath.Join(claudeDir, "commands")+":/home/agent/.claude/commands:ro")
	// CLAUDE.md is no longer bind-mounted; it's staged via stageClaudeMD
	// on the host side so SAFE can inject the sandbox preamble.
	require.NotContains(t, joined, "/home/agent/.claude/CLAUDE.md:ro",
		"CLAUDE.md is staged, not bind-mounted")
	require.NotContains(t, joined, "hooks", "hooks was off")
}

func TestExpandMountsSkipsMissingSources(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	// Only skills exists; the rest should not appear even if requested.
	require.NoError(t, os.MkdirAll(filepath.Join(claudeDir, "skills"), 0o700))

	flags := dockerrun.ExpandMounts(claudeDir, config.Customization{
		Skills:   true,
		Commands: true,
		ClaudeMD: true,
	})

	joined := flagsAsString(flags)
	require.Contains(t, joined, "skills")
	require.NotContains(t, joined, "commands")
	require.NotContains(t, joined, "CLAUDE.md")
}

func TestExpandMountsNeverMountsDenylistedItems(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	writeFile(t, filepath.Join(claudeDir, ".credentials.json"), "{}")
	require.NoError(t, os.MkdirAll(filepath.Join(claudeDir, "projects"), 0o700))

	flags := dockerrun.ExpandMounts(claudeDir, config.Customization{
		Skills:     true,
		Commands:   true,
		ClaudeMD:   true,
		Settings:   true,
		Statusline: true,
		Hooks:      true,
		Plugins:    true,
	})

	joined := flagsAsString(flags)
	require.NotContains(t, joined, ".credentials.json")
	require.NotContains(t, joined, "projects")
}

func flagsAsString(flags []string) string {
	s := ""
	for _, f := range flags {
		s += f + " "
	}
	return s
}

func TestExpandStatuslineMountsFromSettings(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))
	writeFile(t, filepath.Join(claudeDir, "settings.json"),
		`{"statusLine":{"type":"command","command":"sh ~/.claude/statusline-command.sh"}}`)
	writeFile(t, filepath.Join(claudeDir, "statusline-command.sh"), "#!/bin/sh\necho hi\n")

	flags := dockerrun.ExpandStatuslineMounts(claudeDir, config.Customization{Statusline: true})
	require.Contains(t, flagsAsString(flags),
		filepath.Join(claudeDir, "statusline-command.sh")+":/home/agent/.claude/statusline-command.sh:ro")
}

func TestExpandStatuslineMountsAlternateFilename(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))
	writeFile(t, filepath.Join(claudeDir, "settings.json"),
		`{"statusLine":{"command":"~/.claude/my-custom-bar.sh"}}`)
	writeFile(t, filepath.Join(claudeDir, "my-custom-bar.sh"), "#!/bin/sh\n")

	flags := dockerrun.ExpandStatuslineMounts(claudeDir, config.Customization{Statusline: true})
	require.Contains(t, flagsAsString(flags), "my-custom-bar.sh:/home/agent/.claude/my-custom-bar.sh:ro")
}

func TestExpandStatuslineMountsSkipsWhenDisabled(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))
	writeFile(t, filepath.Join(claudeDir, "settings.json"),
		`{"statusLine":{"command":"sh ~/.claude/statusline-command.sh"}}`)
	writeFile(t, filepath.Join(claudeDir, "statusline-command.sh"), "#!/bin/sh\n")

	flags := dockerrun.ExpandStatuslineMounts(claudeDir, config.Customization{Statusline: false})
	require.Empty(t, flags, "Statusline=false must not mount anything")
}

func TestExpandStatuslineMountsSkipsMissingFile(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))
	// settings references a script that doesn't exist on host
	writeFile(t, filepath.Join(claudeDir, "settings.json"),
		`{"statusLine":{"command":"sh ~/.claude/does-not-exist.sh"}}`)

	flags := dockerrun.ExpandStatuslineMounts(claudeDir, config.Customization{Statusline: true})
	require.Empty(t, flags, "missing script must be silently skipped")
}

func TestExpandStatuslineMountsIgnoresNonClaudePaths(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))
	// Absolute path outside ~/.claude — SAFE should not try to mount it.
	writeFile(t, filepath.Join(claudeDir, "settings.json"),
		`{"statusLine":{"command":"/usr/local/bin/my-bar"}}`)

	flags := dockerrun.ExpandStatuslineMounts(claudeDir, config.Customization{Statusline: true})
	require.Empty(t, flags, "non-~/.claude paths must be ignored")
}
