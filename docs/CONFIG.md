# SAFE Configuration Reference

SAFE reads YAML from two locations, merged in order. The project file overrides the global file. See [Merge rules](#merge-rules) below for the exact semantics.

| File | Scope | Required |
|---|---|---|
| `$XDG_CONFIG_HOME/safe/safe.yaml` (typically `~/.config/safe/safe.yaml`) | Global | No |
| `./safe.yaml` | Per-project | No |

## Full example

```yaml
agents:
  claude:
    image: ghcr.io/<org>/safe-runtime:0.1.0
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url_env: ANTHROPIC_BASE_URL
    base_url: https://api.anthropic.com
    auth_header: Authorization     # or x-api-key
    auth_scheme: Bearer            # empty for x-api-key-style headers
    locked_tools: [Read, Write, Edit, Bash, Glob, Grep, NotebookEdit]
    env:
      DISABLE_TELEMETRY: "1"
      CLAUDE_CODE_DISABLE_AUTOUPDATER: "1"
    customization:
      skills:     true
      commands:   true
      claudemd:   true
      settings:   false
      statusline: false
      hooks:      false
      plugins:    false

allowlist:
  - api.anthropic.com
  - registry.npmjs.org
  - pypi.org
  - files.pythonhosted.org
  - proxy.golang.org
  - sum.golang.org
  - deb.debian.org

upstream_dns:
  - 1.1.1.1
  - 1.0.0.1

mounts: []                      # opt-in extras only, default empty
env_passthrough: [TERM, LANG, TZ]

resources:
  memory: 4g
  pids: 256

audit:
  enabled: true
  host_path: ~/.local/share/safe/audit.log

rtk:
  enabled: true
```

## Schema

### Top-level

| Key | Type | Required | Default | Description |
|---|---|---|---|---|
| `agents` | map[string]Agent | yes | — | Agent registry; key is the name passed on the CLI (`safe <name>`). |
| `allowlist` | []string | yes | — | FQDNs (or `*.fqdn` wildcards) the in-container DNS resolver will answer. Anything not listed gets NXDOMAIN. Validated against an RFC-ish FQDN regex; IPs are rejected. |
| `upstream_dns` | []string | yes | — | Upstream resolver IPs (v4) for safe-dns. Only reachable by uid 200 (firewall) per the nftables ruleset. |
| `mounts` | []string | no | `[]` | Reserved for future opt-in extra mounts. |
| `env_passthrough` | []string | no | `[TERM, LANG, TZ]` | Host env vars allowed into the container. Everything else (`HOME`, `PATH`, …) is blocked. |
| `resources.memory` | string | no | `4g` | Docker `--memory` value. |
| `resources.pids` | int | no | `256` | Docker `--pids-limit`. |
| `audit.enabled` | bool | no | `true` | Whether safe-dns writes the JSONL audit log. |
| `audit.host_path` | string | no | `~/.local/share/safe/audit.log` | Host path mounted as the audit destination (planned). |
| `rtk.enabled` | bool | no | `true` | Run `rtk init -g` at startup and set `RTK_TELEMETRY_DISABLED=1` in the agent env. |

### `rtk`

Controls the in-container [RTK](https://github.com/rtk-ai/rtk) token optimiser.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Run `rtk init -g` at startup and set `RTK_TELEMETRY_DISABLED=1` in the agent env. RTK intercepts Bash command output and compresses it 60–90% before it reaches the LLM. |

Telemetry is unconditionally disabled (the container is firewalled; outbound connections to RTK telemetry endpoints would be dropped by nftables regardless).

To tune RTK's behaviour (excluded commands, tee mode, etc.), mount your `~/.config/rtk/config.toml` into the container:

```yaml
mounts:
  - ~/.config/rtk/config.toml:/home/agent/.config/rtk/config.toml:ro
```

### Agent

| Key | Type | Required | Description |
|---|---|---|---|
| `image` | string | yes | Docker image reference for the runtime. |
| `entrypoint` | string | yes | Binary name to exec inside the container (e.g. `claude`). |
| `auth_env` | string | no | Host env var holding the LLM API key (e.g. `ANTHROPIC_API_KEY`). |
| `base_url_env` | string | no | Env var the agent reads for its base URL (e.g. `ANTHROPIC_BASE_URL`). |
| `base_url` | string | no | The real upstream LLM endpoint. **Must be in the `allowlist`.** |
| `auth_header` | string | no | Header to inject the key into. Default `Authorization`. |
| `auth_scheme` | string | no | Scheme prefix. Default `Bearer`. Empty for `x-api-key`-style headers. |
| `locked_tools` | []string | yes | Subset of Claude Code's tool list to expose. Unknown names are a hard error. |
| `env` | map[string]string | no | Extra env vars to set inside the container for the agent. |
| `customization.*` | bool | no | Opt-in mounts of `~/.claude/<subdir>` (read-only). See below. |

### Customization flags

Each is a boolean that opts a single read-only mount in or out. Default for unknown agents is "all off". The denylist (`.credentials.json`, `projects/`, `.claude.json`, anything under `.git/` inside `.claude/`) is enforced by code and **cannot** be overridden.

| Flag | Default | Mounts |
|---|---|---|
| `skills`     | on  | `~/.claude/skills/`     → `/home/agent/.claude/skills:ro` |
| `commands`   | on  | `~/.claude/commands/`   → `/home/agent/.claude/commands:ro` |
| `claudemd`   | on  | `~/.claude/CLAUDE.md`   → `/home/agent/.claude/CLAUDE.md:ro` |
| `settings`   | off | `~/.claude/settings.json` → `/home/agent/.claude/settings.json:ro` |
| `statusline` | off | `~/.claude/statusline.sh` → `/home/agent/.claude/statusline.sh:ro` |
| `hooks`      | off | `~/.claude/hooks/`      → `/home/agent/.claude/hooks:ro` |
| `plugins`    | off | `~/.claude/plugins/`    → `/home/agent/.claude/plugins:ro` |

Defaults are "off" for anything that executes a script on the host (hooks, statusline) because even though they're sandboxed, narrower is better.

## Merge rules

When both `~/.config/safe/safe.yaml` and `./safe.yaml` exist, SAFE merges them as follows (matches RAGE):

- **Slices append.** `allowlist: [a]` in global plus `allowlist: [b]` in project ⇒ `[a, b]`.
- **Maps merge per key.** `agents.claude.env: {A: 1}` plus `agents.claude.env: {B: 2}` ⇒ `{A: 1, B: 2}`. Project keys overwrite global keys.
- **Scalars: project replaces global** if non-zero.
- **Customization** is a special case: if the project's `customization` struct has any field set, it **replaces** the global one entirely. Otherwise the global is preserved.

You can sanity-check the result with `safe --print-config`.

## Validation

SAFE validates the merged config at startup. It refuses to run if:

- An allowlist entry isn't a valid FQDN or `*.fqdn` wildcard. IPs are not allowed.
- An agent's `image` is missing.
- An agent's `locked_tools` is empty or contains a name SAFE doesn't recognise.
- The agent's `base_url` host isn't on the allowlist.
- `upstream_dns` is empty.

The CLI surface for this is `safe --doctor`, which runs the same validation plus checks that Docker is reachable, the image is pulled, and the auth env var is set.
