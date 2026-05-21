# SAFE — Sandboxed Agent For Engineering

Run AI coding agents (Claude Code) inside a hardened Docker sandbox: default-deny outbound network, FQDN-anchored allowlist, OAuth/API credentials isolated from the agent process, your `$PWD` mounted as the workspace.

```bash
safe claude            # like running `claude`, but sandboxed
safe --shell           # bash inside the sandbox, no agent
safe --doctor          # pre-flight checks
safe init              # scaffold .safe/safe.yaml in this project
```

## Why

AI agents have shell access, filesystem read/write, and outbound network. A prompt injection or malicious skill goes from interesting risk to direct exposure of your AWS keys, SSH keys, git push access, and OAuth tokens. SAFE bounds the blast radius to:

- This project's `$PWD` (bind-mounted at `/workspace`).
- The FQDNs explicitly in your allowlist.
- A small writable persistent cache (`~/.cache`, `~/.claude/projects`).

Even if the agent goes off the rails it can't reach AWS, can't read host SSH keys, can't push to GitHub, can't exfiltrate your Anthropic credentials.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

## How it works (one paragraph)

A single container. `safe-init` (PID 1, root briefly) reads an OAuth/API credential from the host once at startup over a one-shot TCP loopback, hands it to `safe-keyholder` (uid 201) in memory only, then drops privileges and execs the agent (uid 1000). `safe-dns` (uid 200, `CAP_NET_ADMIN`) runs an in-container resolver that returns NXDOMAIN for anything not in your `allowlist` and dynamically updates nftables sets per allowed lookup. Every outbound LLM request from the agent goes through keyholder's HTTPS proxy on `127.0.0.1:8443`, which strips the agent's dummy `Authorization` header and substitutes the real one in flight. The agent uid never sees the real credential.

## Install

```bash
git clone https://github.com/rdoorn/safe && cd safe
make install                              # /usr/local/bin/safe (prompts for sudo)
docker buildx build -t safe-runtime:dev . # builds the runtime image
safe --doctor                             # confirm everything's set
```

Override the install path with `make install PREFIX=$HOME/.local` for no-sudo.

## First-time setup for a project

```bash
cd ~/code/my-project
safe init                       # writes .safe/safe.yaml, adds .safe/ to .gitignore
$EDITOR .safe/safe.yaml         # tweak allowlist, tool versions, etc.
safe claude                     # go
```

`safe init` is idempotent — it won't overwrite an existing config without `--force`, and adds `.safe/` to ignore files only if missing.

### Authentication

Two mutually-exclusive modes; `safe init` ships an OAuth template.

**OAuth (Claude.ai / Claude Enterprise):**

```yaml
agents:
  claude:
    auth_credentials_file: ~/.claude/.credentials.json
    auth_refresh_url: https://console.anthropic.com/v1/oauth/token
```

Run `claude login` once on your host (outside SAFE — it opens a browser). The token lands in:

- **macOS**: Keychain (`Claude Code-credentials`). SAFE reads via `security`.
- **Linux**: Secret Service (GNOME Keyring / KDE Wallet / etc.) via libsecret. SAFE reads via `secret-tool` (install `libsecret-tools`).
- **Either**: `~/.claude/.credentials.json` fallback if the keychain lookup fails.

The credential never enters the container's filesystem or the agent's process memory.

**API key (Anthropic Console):**

```yaml
agents:
  claude:
    auth_env: ANTHROPIC_API_KEY
    auth_header: Authorization
    auth_scheme: Bearer
```

`export ANTHROPIC_API_KEY=sk-...` on the host. Same isolation — keyholder holds it; the agent uid sees only a `dummy` placeholder.

## What's in the sandbox

Pre-installed in the runtime image:

- **Editors / shell tools**: `git`, `curl`, `wget`, `jq`, `make`, `ripgrep`, `fd`, `vim-tiny`, `less`.
- **Languages**: Go 1.25, Python 3 (Debian default), Node (Debian default), plus **pyenv** + **fnm** for per-project version pinning.
- **Package managers**: **`pnpm`** with lifecycle scripts denied by default. `npm` and `yarn` are locked off; `apt` is locked off at runtime.
- **Claude Code** at `/usr/local/bin/claude`.

### Per-project tool versions

Pin language versions in `.safe/safe.yaml`:

```yaml
agents:
  claude:
    tools:
      python: "3.14.0"
      node: "22.10.0"
```

First run invokes `pyenv install` / `fnm install` and stashes the install in `.safe/tools/{python,node}/<version>/`. Subsequent runs reuse it. The dir is gitignored.

Go has no `tools.go` field — pin via `go.mod`'s `toolchain go1.X.Y` directive; Go auto-downloads matching toolchains (cached on the persistent project volume).

### Package-manager safety

- Only `pnpm` is on the agent's PATH.
- `NPM_CONFIG_IGNORE_SCRIPTS=true` by default — pnpm skips `pre/post/install` scripts unless you opt-in per-package (`pnpm approve-builds <pkg>`). This blocks the dominant npm-supply-chain attack vector.
- `apt`, `apt-get`, `dpkg` are root-only — agent uid can't install system packages.

### Persistence across runs

Two docker named volumes per project (keyed on a sha1 of the project path):

- `safe-cache-<hash>` → `/home/agent/.cache` — Go modules, Go toolchains, pip wheels, pnpm store, build artifacts.
- `safe-claude-<hash>` → `/home/agent/.claude/projects` — claude session JSONL files; `/resume` works across `safe claude` runs.

Inspect with `docker volume ls | grep safe-`. Switching projects gets fresh volumes.

## Shell alias — make it transparent

Add to your shell rc:

```bash
alias claude='safe claude'
alias safesh='safe --shell'
```

Reload. Now `claude "explain the auth flow"` always runs sandboxed. Bypass with `\claude` if you ever need the real binary.

## Global vs per-project config

SAFE reads two YAML files and merges (per-project overrides global):

| File | Purpose |
|---|---|
| `~/.config/safe/safe.yaml` | Global defaults (image tag, default allowlist additions). |
| `<cwd>/.safe/safe.yaml` | Per-project, created by `safe init`. |

Inspect the merged result with `safe --print-config`. Full schema in [`docs/CONFIG.md`](docs/CONFIG.md).

## What gets blocked

From inside the sandbox:

```bash
curl https://1.2.3.4                   # timeout — no raw-IP nftables rule
dig @8.8.8.8 example.com               # timeout — DNS exfil blocked
curl https://evil.example.com          # NXDOMAIN — not allowlisted
cat ~/.ssh/id_rsa                      # not mounted
echo "$ANTHROPIC_API_KEY"              # =dummy (keyholder substitutes real)
apt install something                  # permission denied — apt is locked
npm install foo                        # permission denied — pnpm only
git push                               # github.com not in default allowlist
```

What works:

```bash
curl https://api.anthropic.com         # via keyholder proxy
go test ./...                          # local tooling
git commit -am "fix"                   # local-only operations
pnpm install                           # with ignore-scripts=true
$EDITOR src/main.go                    # workspace is writable
```

Full manual walkthrough in [`docs/TEST.md`](docs/TEST.md).

## How it compares to related tools

| Tool | Role |
|---|---|
| [RAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/rage) | Userspace MITM proxy wrapping a single agent. Command validation, secret redaction, prompt rewriting. |
| [CAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/cage) | Per-project Docker orchestrator with Forgejo as a review gate; runs RAGE inside each container. |
| [Argus](https://sbp.gitlab.schubergphilis.com/Security/tools/argus) | Host-side eBPF observer/enforcer (Tetragon). |
| **SAFE** | **Single container, single command, default-deny network, minimal moving parts.** |

SAFE is intentionally simpler than the trio combined — a lighter alternative for the common "I just want to run an agent safely on my Mac/Linux box" case.

## Docs

- [`docs/CONFIG.md`](docs/CONFIG.md) — full `safe.yaml` schema.
- [`docs/CUSTOM.md`](docs/CUSTOM.md) — building a custom runtime image with extra tools.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, defences, known limitations.
- [`docs/TEST.md`](docs/TEST.md) — manual verification scenarios.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — deferred features (Rust/Ruby version managers, etc.).
- [`docs/plans/2026-05-15-safe-design.md`](docs/plans/2026-05-15-safe-design.md) — full architecture and design rationale.

## Status

Early but functional. The host CLI, four in-container daemons, runtime image, and end-to-end flow work and have been used to run claude interactive sessions (including OAuth login flow). What's still loose:

- No release artifacts yet — build from source.
- CI-side e2e suite is a manual walkthrough (`docs/TEST.md`).

If you find something that should be blocked but isn't, [file an issue](https://github.com/rdoorn/safe/issues).

## License

MIT. See [LICENSE](LICENSE).
