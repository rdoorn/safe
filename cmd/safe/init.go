package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const initTemplate = `# SAFE configuration for this project.
# See docs/CONFIG.md for the full schema reference.
# Validate the merged result with: safe --print-config

agents:
  claude:
    image: ghcr.io/rdoorn/safe-runtime:0.1.0
    entrypoint: claude
    base_url_env: ANTHROPIC_BASE_URL
    base_url: https://api.anthropic.com

    # Choose exactly ONE auth mode:
    #
    # OAuth (Claude.ai / Claude Enterprise — default): keyholder reads
    # the credentials.json that ` + "`claude login`" + ` writes on the host.
    auth_credentials_file: ~/.claude/.credentials.json
    auth_refresh_url: https://console.anthropic.com/v1/oauth/token
    #
    # API key (Anthropic Console): uncomment and remove the two lines above.
    # auth_env: ANTHROPIC_API_KEY
    # auth_header: Authorization
    # auth_scheme: Bearer

    locked_tools: [Read, Write, Edit, Bash, Glob, Grep, NotebookEdit]
    env:
      DISABLE_TELEMETRY: "1"
      CLAUDE_CODE_DISABLE_AUTOUPDATER: "1"
    customization:
      skills: true
      commands: true
      claudemd: true
      settings: false
      statusline: false
      hooks: false
      plugins: false

# FQDNs the agent is allowed to reach. Anything else returns NXDOMAIN.
# Edit this list for your project's API endpoints.
allowlist:
  - api.anthropic.com
  - console.anthropic.com    # needed for OAuth token refresh; remove for API-key mode
  - registry.npmjs.org
  - pypi.org
  - files.pythonhosted.org
  - proxy.golang.org
  - sum.golang.org
  - deb.debian.org

upstream_dns:
  - 1.1.1.1
  - 1.0.0.1

env_passthrough: [TERM, LANG, TZ]

resources:
  memory: 4g
  pids: 256

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
