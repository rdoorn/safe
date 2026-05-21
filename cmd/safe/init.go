package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const ignoreEntry = ".safe/"

// otherIgnoreFiles is the list of non-git ignore files that runInit will
// AUGMENT if they already exist. It will NEVER create them — that's the
// user's tooling's job, not SAFE's. Only .gitignore gets the create-if-
// missing treatment, because SAFE assumes any project using SAFE is
// version-controlled.
var otherIgnoreFiles = []string{
	".dockerignore",
	".eslintignore",
	".prettierignore",
	".npmignore",
}

const initTemplate = `# SAFE configuration for this project.
# Full schema: docs/CONFIG.md
# Inspect merged result: safe --print-config
#
# Convention in this file: required and non-default fields are uncommented.
# Optional fields at their default value are commented out so you can see
# the full surface area without cluttering the active config.

agents:
  claude:
    # Required: safe-runtime container image.
    image: ghcr.io/rdoorn/safe-runtime:0.1.0

    # Required: binary the container exec's as the agent.
    entrypoint: claude

    # -------- Authentication: choose exactly one mode --------
    #
    # OAuth mode (Claude.ai / Claude Enterprise). SAFE reads the
    # credentials.json that ` + "`claude login`" + ` wrote on the host.
    auth_credentials_file: ~/.claude/.credentials.json
    # auth_refresh_url: https://console.anthropic.com/v1/oauth/token   # default
    #
    # API-key mode (Anthropic Console). To switch: comment the line above
    # and uncomment these:
    # auth_env: ANTHROPIC_API_KEY
    # auth_header: Authorization   # default
    # auth_scheme: Bearer          # default; use "" for x-api-key-style headers

    # Required: upstream LLM endpoint. Host MUST be on allowlist below.
    base_url: https://api.anthropic.com
    # base_url_env: ANTHROPIC_BASE_URL    # default; env var passed to the agent

    # Required: Claude Code tools the agent may use.
    # Unknown names error at config validation time.
    locked_tools: [Read, Write, Edit, Bash, Glob, Grep, NotebookEdit]

    # Extra args appended to the agent's command line on every run,
    # before any CLI args you pass after "safe claude". Useful for
    # always-on flags like --dangerously-skip-permissions (bypasses
    # claude's trust + per-tool permission prompts; the SAFE sandbox
    # is the security boundary, so the prompts are mostly noise).
    # extra_args: []
    # extra_args:
    #   - --dangerously-skip-permissions

    # Per-project language-runtime versions. SAFE provisions these on
    # first run into <cwd>/.safe/tools/, then reuses on subsequent runs.
    # Exact pinned versions only (no ranges). Comment out if you want
    # to use whatever ships in the image.
    #
    # NOTE: there is no "tools.go" field. Go pins its own toolchain
    # natively via the "toolchain goX.Y.Z" directive in your go.mod;
    # the Go binary auto-downloads matching toolchains (cached on the
    # persistent project volume). See go.dev/doc/toolchain.
    # tools:
    #   python: "3.14.0"
    #   node: "22.10.0"

    # Extra env vars set inside the container for the agent process.
    env:
      DISABLE_TELEMETRY: "1"
      CLAUDE_CODE_DISABLE_AUTOUPDATER: "1"

    # Opt-in read-only bind-mounts of subdirs under ~/.claude on the host.
    # Defaults below match SAFE's recommended posture: safe (markdown)
    # things on, executable/script-bearing things off.
    customization:
      skills: true       # default
      commands: true     # default
      claudemd: true     # default
      settings: true     # default; ~/.claude/settings.json (RO)
      state: true        # default; ~/.claude.json (RO) — has theme prefs
      # statusline: false # default; executable runs as agent uid
      # hooks: false      # default; scripts run as agent uid
      # plugins: false    # default

# FQDNs the agent is allowed to reach. Anything else returns NXDOMAIN.
# Edit this list for your project's API endpoints.
allowlist:
  - api.anthropic.com
  - console.anthropic.com    # OAuth token refresh; remove if using API-key mode
  - registry.npmjs.org
  - pypi.org
  - files.pythonhosted.org
  - proxy.golang.org
  - sum.golang.org
  - deb.debian.org
  # Required if you use the "tools:" block to provision pyenv/fnm versions:
  - www.python.org           # pyenv install source tarballs
  - nodejs.org               # fnm install prebuilt node tarballs
  - github.com               # fnm pulls from Schniz/fnm releases on GH
  - objects.githubusercontent.com  # GH releases CDN

# Upstream DNS resolvers safe-dns forwards allowed queries to. Reachable
# only by the firewall uid (200) inside the container.
upstream_dns:
  - 1.1.1.1
  - 1.0.0.1

# Host env vars to pass through into the container. Everything else is
# stripped. Default below is the conservative minimum.
env_passthrough: [TERM, LANG, TZ]

# Opt-in extra Linux capabilities granted to the container. Allowed:
#   SYS_ADMIN        — enables /proc hidepid=2 (hides other uids' PIDs
#                      from the agent uid).
#   SYS_PTRACE       — diagnostic only; lets a debugger attach across
#                      uids inside the container.
#   NET_BIND_SERVICE — bind privileged ports inside the container.
# Anything not on this list must be source-edited; see internal/config/validate.go.
# extra_caps: []

# Docker resource limits. Defaults shown.
# resources:
#   memory: 4g    # default
#   pids: 256     # default

# Opt-in extra host bind-mounts beyond $PWD (which is always mounted).
# mounts: []      # default

# JSONL audit log of every DNS allow/deny event.
audit:
  enabled: true
  host_path: ~/.local/share/safe/audit.log
`

// runInit writes a default safe.yaml under <cwd>/.safe/ and ensures the
// project's ignore files exclude that directory. It refuses to overwrite
// an existing safe.yaml unless force is true.
func runInit(out io.Writer, cwd string, force bool) error {
	safeDir := filepath.Join(cwd, ".safe")
	target := filepath.Join(safeDir, "safe.yaml")
	if !force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", target)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", target, err)
		}
	}
	if err := os.MkdirAll(safeDir, 0o755); err != nil { //nolint:gosec // .safe is a project-local state dir; 0755 lets normal tooling read its contents
		return fmt.Errorf("mkdir %s: %w", safeDir, err)
	}
	if err := os.WriteFile(target, []byte(initTemplate), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if err := ensureIgnoreEntry(cwd, ".gitignore", ignoreEntry, true); err != nil {
		return err
	}
	for _, name := range otherIgnoreFiles {
		if err := ensureIgnoreEntry(cwd, name, ignoreEntry, false); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(out, "wrote %s\nNext: edit the allowlist for project-specific endpoints, then run `safe --doctor`.\n", target); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}

// ensureIgnoreEntry guarantees `entry` appears on its own line in
// <cwd>/<name>. If the file is missing and createIfMissing is true, the
// file is created with just `entry`. If the file is missing and
// createIfMissing is false, this is a no-op. If the entry is already
// present (exact line match after Trim), the file is unchanged.
func ensureIgnoreEntry(cwd, name, entry string, createIfMissing bool) error {
	path := filepath.Join(cwd, name)
	data, err := os.ReadFile(path) //nolint:gosec // path constructed from validated cwd + literal filename
	if errors.Is(err, fs.ErrNotExist) {
		if !createIfMissing {
			return nil
		}
		if err := os.WriteFile(path, []byte(entry+"\n"), 0o644); err != nil { //nolint:gosec // user-visible ignore file; needs to be readable by tooling
			return fmt.Errorf("create %s: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil
		}
	}
	prefix := ""
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		prefix = "\n"
	}
	updated := append([]byte{}, data...)
	updated = append(updated, []byte(prefix+entry+"\n")...)
	if err := os.WriteFile(path, updated, 0o644); err != nil { //nolint:gosec // see above
		return fmt.Errorf("update %s: %w", path, err)
	}
	return nil
}
