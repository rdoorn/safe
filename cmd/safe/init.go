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
# Convention: required and SAFE-recommended fields are uncommented.
# Optional fields you might want are commented out so you can see the
# full surface area without cluttering the active config.

agents:
  claude:
    # Required: safe-runtime container image. Build locally with
    # ` + "`docker buildx build -t safe-runtime:dev .`" + ` from the safe repo.
    image: safe-runtime:dev

    # Required: binary the container exec's as the agent.
    entrypoint: claude

    # -------- Authentication: choose exactly one mode --------
    #
    # OAuth mode (Claude.ai / Claude Enterprise). On macOS SAFE reads
    # the token from Keychain (service "Claude Code-credentials"); on
    # Linux from the freedesktop Secret Service via secret-tool; both
    # fall back to ~/.claude/.credentials.json if present. Run
    # ` + "`claude login`" + ` once on the host (outside SAFE) to populate it.
    auth_credentials_file: ~/.claude/.credentials.json
    # auth_refresh_url: https://console.anthropic.com/v1/oauth/token   # default
    #
    # API-key mode (Anthropic Console). To switch: comment the line above
    # and uncomment these:
    # auth_env: ANTHROPIC_API_KEY
    # auth_header: Authorization   # default
    # auth_scheme: Bearer          # default; use "" for x-api-key-style headers

    # Required: upstream LLM endpoint. Host MUST be on the allowlist below.
    base_url: https://api.anthropic.com
    # base_url_env: ANTHROPIC_BASE_URL    # default; env var passed to the agent

    # Required: Claude Code tools the agent may use.
    # Unknown names error at config validation time.
    locked_tools: [Read, Write, Edit, Bash, Glob, Grep, NotebookEdit]

    # Always-on agent CLI flags. The SAFE sandbox is the security
    # boundary, so claude's per-tool permission prompts are noise here.
    # --dangerously-skip-permissions skips them. Comment out the entire
    # block if you prefer claude to prompt before each Bash/Edit/etc.
    extra_args:
      - --dangerously-skip-permissions

    # Per-project language-runtime versions. SAFE invokes pyenv/fnm on
    # first run, stashing the install in <cwd>/.safe/tools/{python,node}/
    # and reusing it on subsequent runs. Exact versions only (no ranges).
    # Uncomment if you need a specific Python/Node; otherwise the image's
    # Debian defaults are used.
    #
    # NOTE: there is no "tools.go" field. Go pins its own toolchain
    # natively via the "toolchain goX.Y.Z" directive in go.mod; Go
    # auto-downloads matching toolchains (cached on the persistent
    # project volume). See go.dev/doc/toolchain.
    # tools:
    #   python: "3.14.0"
    #   node: "22.10.0"

    # Extra env vars set inside the container for the agent process.
    env:
      DISABLE_TELEMETRY: "1"
      CLAUDE_CODE_DISABLE_AUTOUPDATER: "1"

    # Read-only state from your host ~/.claude bind-mounted or staged
    # into the container. SAFE's recommended posture: markdown/config on,
    # executable-bearing items off unless you trust your host's content.
    customization:
      skills: true       # bind-mount ~/.claude/skills (RO)
      commands: true     # bind-mount ~/.claude/commands (RO)
      claudemd: true     # stage ~/.claude/CLAUDE.md (SAFE prepends a sandbox-policy preamble)
      settings: true     # stage ~/.claude/settings.json (SAFE injects safety defaults)
      state: true        # stage ~/.claude.json (theme, trust, project history)
      statusline: true   # bind-mount ~/.claude/statusline.sh; runs as agent uid in container
      # hooks: false     # OPT-IN: ~/.claude/hooks/ scripts exec on hook events as agent uid
      # plugins: false   # OPT-IN: ~/.claude/plugins/ can run arbitrary code

# FQDNs the agent is allowed to reach. Anything else returns NXDOMAIN.
# Edit this list for your project's API endpoints.
allowlist:
  - api.anthropic.com
  - console.anthropic.com          # OAuth token refresh; remove if API-key mode
  - platform.claude.com            # claude session/heartbeat API
  - downloads.claude.ai            # claude code update channel
  - raw.githubusercontent.com      # claude marketplace / plugin metadata
  - registry.npmjs.org             # pnpm registry
  - pypi.org                       # python packages
  - files.pythonhosted.org         # pypi CDN
  - proxy.golang.org               # go modules + auto-toolchains
  - sum.golang.org                 # go checksum DB
  - deb.debian.org                 # used at image build (safe to keep at runtime)
  # Uncomment these only if you use the "tools:" block to provision
  # pyenv/fnm versions on first run:
  # - www.python.org               # pyenv source tarballs
  # - nodejs.org                   # fnm prebuilt node tarballs
  # - github.com                   # fnm pulls from Schniz/fnm GH releases
  # - objects.githubusercontent.com  # GH releases CDN

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

# RTK token optimiser: reduces LLM token consumption 60-90% by filtering
# Bash command output. Enabled by default. Disable if you need raw output.
rtk:
  enabled: true
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
