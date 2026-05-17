package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

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
      # settings: false  # default; settings.json may reference host paths
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

# Upstream DNS resolvers safe-dns forwards allowed queries to. Reachable
# only by the firewall uid (200) inside the container.
upstream_dns:
  - 1.1.1.1
  - 1.0.0.1

# Host env vars to pass through into the container. Everything else is
# stripped. Default below is the conservative minimum.
env_passthrough: [TERM, LANG, TZ]

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

// runInit writes a default safe.yaml to cwd. It refuses to overwrite an
// existing file unless force is true.
func runInit(out io.Writer, cwd string, force bool) error {
	target := filepath.Join(cwd, "safe.yaml")
	if !force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", target, err)
		}
	}
	if err := os.WriteFile(target, []byte(initTemplate), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if _, err := fmt.Fprintf(out, "wrote %s\nNext: edit the allowlist for project-specific endpoints, then run `safe --doctor`.\n", target); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}
