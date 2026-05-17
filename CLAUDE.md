# SAFE — Claude Code session guide

This file is the entry point for Claude Code sessions in this repo. Loaded automatically. Keep it tight.

## What SAFE is

A single hardened Docker container around an AI coding agent. Default-deny outbound network, FQDN-anchored allowlist, LLM auth held by a separate uid the agent can't read. Built around four Go daemons (`safe-init`, `safe-fw`, `safe-dns`, `safe-keyholder`) plus a host CLI (`safe`).

Three uid principals inside the container: `firewall` (200) runs `safe-dns`, `keyholder` (201) runs `safe-keyholder`, `agent` (1000) runs the agent.

## Where to start when you arrive in this repo

| Question | Read |
|---|---|
| Why does the code do *X*? | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — decisions made during implementation, with rationale. |
| Where is *X* implemented? | [`docs/COMPONENTS.md`](docs/COMPONENTS.md) — per-component file map + data flow diagram. |
| What was the original design? | [`docs/plans/2026-05-15-safe-design.md`](docs/plans/2026-05-15-safe-design.md). |
| What's the implementation plan? | [`docs/plans/2026-05-15-safe-implementation.md`](docs/plans/2026-05-15-safe-implementation.md) — milestones, mostly historical now. |
| How does a user use this? | [`README.md`](README.md). |
| What's the config schema? | [`docs/CONFIG.md`](docs/CONFIG.md). |
| What's the threat model? | [`docs/SECURITY.md`](docs/SECURITY.md). |

## File index (jump straight here, skip grep)

### Host CLI — `cmd/safe/`
- [`cmd/safe/main.go`](cmd/safe/main.go) — cobra root, flag wiring, positional dispatch (`init`, agent name).
- [`cmd/safe/run.go`](cmd/safe/run.go) — `runAgent`: loads config, resolves auth secret (API key or OAuth file), builds argv, execs docker, pipes secret to keyholder.
- [`cmd/safe/init.go`](cmd/safe/init.go) — `runInit` writes `safe.yaml` template.
- [`cmd/safe/doctor.go`](cmd/safe/doctor.go) — `--doctor` preflight printing.
- [`cmd/safe/printconfig.go`](cmd/safe/printconfig.go) — `--print-config` YAML dump.

### In-container binaries — `cmd/safe-*/`
- [`cmd/safe-init/main.go`](cmd/safe-init/main.go) — PID 1 orchestrator.
- [`cmd/safe-fw/main.go`](cmd/safe-fw/main.go) — seed nftables once, exit.
- [`cmd/safe-dns/main.go`](cmd/safe-dns/main.go) — DNS server entry; `dnsClientUpstream` wraps `miekg/dns` client.
- [`cmd/safe-keyholder/main.go`](cmd/safe-keyholder/main.go) — HTTP auth proxy entry; `buildTokenSource` picks apikey vs oauth.

### Internal packages — `internal/`
- [`internal/config/`](internal/config/) — schema (`config.go`), loader, merger, validator (mutual-exclusion of `auth_env`/`auth_credentials_file`).
- [`internal/firewall/`](internal/firewall/) — nftables ruleset Build/Render/Apply (Apply shells out, init-time only).
- [`internal/resolver/`](internal/resolver/) — `Server`, `Matcher`, `SetUpdater` (netlink, **not** exec — see ARCHITECTURE.md decision #4), `JSONLAuditor`, `ClampTTL`.
- [`internal/keyholder/`](internal/keyholder/) — `TokenSource` interface + `Key` (static) + `OAuthTokenSource` (refreshes); `Rewriter`/`Proxy`/`Bootstrap`.
- [`internal/initd/`](internal/initd/) — `ForwardSignals`, `DropPrivileges` (linux), `RemountProcHidepid` (linux, best-effort).
- [`internal/dockerrun/`](internal/dockerrun/) — `BuildArgv`, `NewSocketDir`, `PipeKey`, `ExpandMounts` (with denylist).
- [`internal/checks/`](internal/checks/) — `Run` + individual check functions for `safe --doctor`.

### Image and build
- [`Dockerfile`](Dockerfile) — debian forky multi-stage; setcap MUST follow chmod/chgrp (decision #6).
- [`image/seccomp.json`](image/seccomp.json) — explicit syscall allowlist (denies `ptrace`/`bpf`/`mount`/`process_vm_*`).
- [`Makefile`](Makefile) — `build`, `install` (with sudo fallback), `test`, `lint`.
- [`.gitlab-ci.yml`](.gitlab-ci.yml) — fmt → vet → golangci-lint → test → build matrix → image push.

### Docs
- [`docs/CONFIG.md`](docs/CONFIG.md) — full `safe.yaml` schema.
- [`docs/CUSTOM.md`](docs/CUSTOM.md) — building custom runtime images.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model + defences.
- [`docs/TEST.md`](docs/TEST.md) — manual verification scenarios.

## How to work in this repo

- Build everything: `make build` → `bin/{safe,safe-init,safe-fw,safe-dns,safe-keyholder}`.
- Install host binary: `make install` (sudoes if needed; override with `PREFIX=$HOME/.local`).
- Tests: `make test`. Lint: `make lint`. Both must pass before commit.
- Image: `docker-buildx build -t safe-runtime:dev .`.
- After any image-affecting change, **rebuild the image** before re-testing inside it.

## Commit conventions

- One commit per TDD task (overrides global "one commit at end" rule — see `[[feedback-commit-cadence]]` in auto-memory).
- Format: `(feat|fix|docs|ci|refactor|test): <one-line summary>`.
- Never mention Claude/AI/LLM in commit messages or bodies.

## Dependency hygiene

Pin to the latest version **at least 7 days old**. Check `https://proxy.golang.org/<module>/@v/<version>.info` for `Time` before adding/upgrading. Same rule for container base images and CI actions. See `[[feedback-dependency-age]]` in auto-memory.
