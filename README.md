# SAFE — Sandboxed Agent For Engineering

A single-container sandbox for running AI coding agents (Claude Code, opencode, …) with cilium-style FQDN filtering, secret containment, and a curated tool set.

Drop-in usage: `safe claude [args...]` works like `claude [args...]` but inside a hardened Docker container with `$PWD` mounted as the workspace and a **default-deny** network.

## Status

Early implementation. The host CLI and the four in-container binaries are written and unit-tested; the container image is plausible but unbuilt; end-to-end integration runs need a real Linux Docker daemon. **Not yet ready for daily use.** See [the implementation plan](docs/plans/2026-05-15-safe-implementation.md) for what's done and what isn't.

## What it does

- **Default-deny outbound network.** The container's nftables `OUTPUT` chain drops everything that isn't explicitly allowed.
- **FQDN allowlist via DNS.** An in-container DNS resolver (safe-dns) only resolves names on the allowlist. When it does, it dynamically punches an nftables rule open for the resolved IP, with a clamped TTL. Raw IP connections never work — there's no rule for an address that didn't come through the resolver.
- **API key isolated from the agent.** Your `ANTHROPIC_API_KEY` is piped to a `keyholder` proxy process (uid 101), not to the agent (uid 1000). The keyholder injects the `Authorization` header on outbound calls. The agent can never read, echo, or exfiltrate the key.
- **Curated tools, locked down.** The image ships with git, gh, ripgrep, fd, jq, Go, Python, and Node — no apt at runtime. Agent tool list is restricted via Claude Code env vars.
- **Read-only rootfs, no caps, seccomp profile.** `--cap-drop ALL --cap-add NET_ADMIN`, `--read-only`, `--security-opt no-new-privileges`, custom seccomp blocking `ptrace`, `bpf`, `mount`, `process_vm_readv`, and friends.
- **No host secrets bind-mounted.** No `~/.ssh`, no `~/.aws`, no SSH agent forwarding, no docker socket. The host environment is **not** passed through — explicit allowlist only.

## Comparison

| Tool | Role |
|---|---|
| [RAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/rage) | Userspace MITM proxy wrapping a single agent process. Bash command validation, secret redaction, prompt rewriting. |
| [CAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/cage) | Per-project Docker orchestrator with Forgejo as a review gate; runs rage inside each container. |
| [Argus](https://sbp.gitlab.schubergphilis.com/Security/tools/argus) | Host-side eBPF observer/enforcer using Tetragon. |
| **SAFE** | **Single container, single command, default-deny network, minimal moving parts.** |

SAFE is intentionally simpler than CAGE + RAGE + Argus combined. It's not a replacement; it's a lighter alternative for the common "I just want to run an agent safely on my Mac" case.

## Usage (intended)

```bash
# Pre-flight check
safe --doctor

# Run Claude in the sandbox with your project mounted at /workspace
ANTHROPIC_API_KEY=sk-... safe claude

# Pass args through to the agent
safe claude --resume

# Drop into a bash shell inside the sandbox for poking around
safe --shell

# Inspect the merged config
safe --print-config
```

## Configuration

`safe` reads `$XDG_CONFIG_HOME/safe/safe.yaml` (global) and `./safe.yaml` (project), merging the project layer on top. See [docs/CONFIG.md](docs/CONFIG.md) for the full schema.

## Design

- [`docs/plans/2026-05-15-safe-design.md`](docs/plans/2026-05-15-safe-design.md) — architecture, threat model, component reference.
- [`docs/plans/2026-05-15-safe-implementation.md`](docs/plans/2026-05-15-safe-implementation.md) — implementation plan (in progress).
- [`docs/CONFIG.md`](docs/CONFIG.md) — config schema reference.
- [`docs/CUSTOM.md`](docs/CUSTOM.md) — building a custom runtime image with extra tools.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, defences, known limitations.

## Build from source

Requires Go 1.25+, a recent golangci-lint, and Docker (for the runtime image).

```bash
make build         # five binaries -> bin/
make test          # unit tests
make lint          # golangci-lint
docker buildx build -t ghcr.io/<org>/safe-runtime:dev .
```

## License

MIT. See [LICENSE](LICENSE).
