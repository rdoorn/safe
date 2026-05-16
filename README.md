# SAFE — Sandboxed Agent For Engineering

`safe claude` works like `claude`, except your agent runs inside a hardened Docker container with a default-deny network, FQDN-based allowlist, and your API key isolated from the agent process. Your `$PWD` is mounted as the workspace. Nothing else from your host is exposed.

```bash
safe claude            # like running `claude`, but sandboxed
safe --shell           # bash inside the sandbox, no agent
safe --doctor          # pre-flight checks
safe init              # scaffold safe.yaml in this project
```

## Why

AI coding agents are powerful tools that you give shell access, your filesystem, and an outbound network connection. SAFE shrinks that blast radius to: just this project's directory, plus a small list of FQDNs you explicitly allow. Even if the agent goes off the rails — prompt injection, malicious skill, a compromised model — it can't reach AWS, can't read your SSH keys, can't push to GitHub, and can't exfiltrate your API key.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

## Install

You need two things: the `safe` host binary and the `safe-runtime` container image.

### 1. Host binary

Build from source (this repo) until releases exist:

```bash
git clone <this-repo> && cd safe
make build
sudo install -m 0755 bin/safe /usr/local/bin/safe
safe --version
```

### 2. Container image

Build it locally with `docker buildx`:

```bash
docker buildx build -t ghcr.io/rdoorn/safe-runtime:0.1.0 .
```

Or, once releases are cut, pull it:

```bash
docker pull ghcr.io/rdoorn/safe-runtime:0.1.0
```

### 3. Confirm with `--doctor`

```bash
safe --doctor
# [OK] docker reachable           docker 28.x.x
# [OK] config valid               schema and invariants satisfied
# [OK] image present              ghcr.io/rdoorn/safe-runtime:0.1.0
# [OK] ANTHROPIC_API_KEY set      present
```

If any line is `[FAIL]`, the message tells you what to fix.

## Shell aliases — make it transparent

The easiest way to use SAFE day-to-day is to shadow `claude` (and any other agents you use) with a shell alias. Then `claude` always runs sandboxed; you can't accidentally forget the wrapper.

Add to **`~/.zshrc`** (or `~/.bashrc`):

```bash
# Always sandbox the AI agents
alias claude='safe claude'
alias opencode='safe opencode'

# Convenience: drop into a sandbox shell in the current project
alias safesh='safe --shell'
```

Reload with `source ~/.zshrc` (or open a new terminal). Now:

```bash
cd ~/code/my-project
claude "explain the auth flow"   # actually runs `safe claude "..."`
```

If you ever need the real `claude` binary, bypass the alias with `\claude` (backslash) or `command claude`.

## First-time setup for a project

```bash
cd ~/code/my-project

# Drop a default safe.yaml in the project root
safe init
# wrote /Users/you/code/my-project/safe.yaml

# Edit allowlist to add anything this project needs to reach
$EDITOR safe.yaml

# Sanity check
safe --doctor

# Go
claude       # or `safe claude` if you didn't set up the alias
```

`safe init` will refuse to overwrite an existing `safe.yaml` — use `safe init --force` if you really mean it.

### Authentication

SAFE supports two mutually-exclusive auth modes. `safe init` scaffolds **OAuth** by default (the Claude.ai / Claude Enterprise flow). Switch by editing the agent block in `safe.yaml`:

**OAuth (default — Claude.ai, Claude Enterprise):**
```yaml
agents:
  claude:
    auth_credentials_file: ~/.claude/.credentials.json
    auth_refresh_url: https://console.anthropic.com/v1/oauth/token
```
Run ` + "`claude login`" + ` on your host **once** (outside SAFE — it opens a browser). That writes `~/.claude/.credentials.json` on the host. SAFE reads those credentials, pipes them into the keyholder, and refreshes the access token via `console.anthropic.com` when it expires. The agent never sees the tokens; the host `.credentials.json` file is never mounted into the container.

> Make sure `console.anthropic.com` is on your `allowlist` — `safe init` adds it by default.

**API key (Anthropic Console accounts):**
```yaml
agents:
  claude:
    auth_env: ANTHROPIC_API_KEY
    auth_header: Authorization
    auth_scheme: Bearer
```
And on the host:
```bash
export ANTHROPIC_API_KEY=sk-...
```
The key is piped to keyholder once at container start and never enters the agent's environment.

`safe --doctor` checks that whichever mode you chose is properly configured.

## Global vs per-project config

SAFE reads two YAML files and merges them:

| File | Purpose |
|---|---|
| `~/.config/safe/safe.yaml` | Your global defaults (image tag, default allowlist, etc.). Create it once with `cp $(safe init && cat safe.yaml) ~/.config/safe/safe.yaml`, or just write it by hand. |
| `./safe.yaml` | Per-project overrides. Allowlist entries append onto the global; agent fields can extend or replace. |

Inspect the merged result anytime with `safe --print-config`. See [`docs/CONFIG.md`](docs/CONFIG.md) for the schema.

## What's in the sandbox

The `safe-runtime` image ships with: `git`, `curl`, `wget`, `jq`, `make`, `ripgrep`, `fd`, Go 1.25, Python 3.13, Node 24, npm, and Claude Code. No apt/yum/dnf at runtime — the image is read-only.

Need extra tools (`gh`, `terraform`, a database client, an SDK)? Build a custom image FROM `safe-runtime` and point your `safe.yaml` at it. See [`docs/CUSTOM.md`](docs/CUSTOM.md).

## What gets blocked

These all FAIL from inside the sandbox:

```bash
# No raw IPs ever — no nftables rule exists for them
curl https://1.2.3.4                   # timeout

# No DNS exfil — only the firewall uid can reach upstream resolvers
dig @8.8.8.8 example.com               # timeout

# No FQDN that isn't on the allowlist
curl https://evil.example.com          # DNS resolution fails

# No reading host credentials — nothing's mounted
cat ~/.ssh/id_rsa                      # no such file
echo "$ANTHROPIC_API_KEY"              # empty (held by keyholder)

# No git push (github.com deliberately off the default allowlist)
git push                               # auth fails or DNS fails
```

These WORK:

```bash
curl https://api.anthropic.com         # if it's in the allowlist
go test ./...                          # local tools fine
git commit -am "fix"                   # local-only operations
$EDITOR src/main.go                    # workspace is writable
```

Run [`docs/TEST.md`](docs/TEST.md) for a full manual verification walkthrough.

## How it compares

| Tool | Role |
|---|---|
| [RAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/rage) | Userspace MITM proxy wrapping a single agent process. Command validation, secret redaction, prompt rewriting. |
| [CAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/cage) | Per-project Docker orchestrator with Forgejo as a review gate; runs RAGE inside each container. |
| [Argus](https://sbp.gitlab.schubergphilis.com/Security/tools/argus) | Host-side eBPF observer/enforcer using Tetragon. |
| **SAFE** | **Single container, single command, default-deny network, minimal moving parts.** |

SAFE is intentionally simpler than the trio combined — a lighter alternative for the common "I just want to run an agent safely on my Mac" case.

## Docs

- [`docs/CONFIG.md`](docs/CONFIG.md) — full `safe.yaml` schema reference.
- [`docs/CUSTOM.md`](docs/CUSTOM.md) — building a custom runtime image with extra tools.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, defences, known limitations.
- [`docs/TEST.md`](docs/TEST.md) — manual verification scenarios.
- [`docs/plans/2026-05-15-safe-design.md`](docs/plans/2026-05-15-safe-design.md) — full architecture and design rationale.

## Status

Early. The host CLI, the four in-container daemons, the image, and end-to-end runtime are working and tested. What's still loose:

- No release artifacts yet (binary downloads, signed images). Build from source.
- No CI-side e2e suite yet (manual scenarios in `docs/TEST.md` cover it).

If you find something that should be blocked but isn't, please [file an issue](https://github.com/rdoorn/safe/issues).

## License

MIT. See [LICENSE](LICENSE).
