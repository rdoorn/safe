# SAFE — Component Map

Per-component reference: role, key files, how it interacts with the rest. Optimised for fast orientation. For *why* decisions were made, see `docs/ARCHITECTURE.md`.

## Host side

### `safe` — host CLI (Go, runs on the developer's machine)

**Role:** The user-facing wrapper. Loads config, validates, builds the `docker run` argv with all hardening flags, pipes the auth secret to the in-container keyholder, forwards stdio, returns the agent's exit code.

**Files:**
- `cmd/safe/main.go` — cobra root command, top-level flags (`--doctor`, `--print-config`, `--shell`, `--force`), positional dispatch (`init`, agent name).
- `cmd/safe/run.go` — `runAgent` end-to-end. `resolveAuthSecret` returns API key (env) or credentials JSON (file). `pipeAuthSecret` writes to the per-run Unix socket.
- `cmd/safe/init.go` — `runInit` writes a default `safe.yaml`. Refuses to overwrite without `--force`.
- `cmd/safe/doctor.go` — runs `internal/checks` preflight, prints OK/FAIL table.
- `cmd/safe/printconfig.go` — dumps merged config as YAML.

**Calls into:** `internal/config`, `internal/checks`, `internal/dockerrun`. Shells out to `docker`.

---

## Inside the container (built into `safe-runtime` image)

### `safe-init` — PID 1

**Role:** Orchestrator. Best-effort `/proc hidepid=2` remount → run `safe-fw` (seeds nftables, exits) → spawn `safe-dns` as uid 200 → read auth secret from `/run/safe/keyholder.sock` → spawn `safe-keyholder` as uid 201 (pipes secret to its stdin, picks mode from agent config) → drop to uid 1000 and exec the agent → forward signals, reap zombies.

**Files:**
- `cmd/safe-init/main.go` — `run()` is the orchestration sequence. `resolveAuthMode` reads `/etc/safe/config.yaml` to decide `--mode=apikey` vs `--mode=oauth`. `readSecretFromSocket` reads bytes until EOF (works for both API-key line and OAuth JSON blob).
- `internal/initd/reaper.go` — `ForwardSignals` relays SIGTERM/SIGINT to the agent PID.
- `internal/initd/procmount_linux.go` — `remountProcHidepid`.
- `internal/initd/userdrop_linux.go` — `dropPrivileges` (used for `safe-dns`/`safe-keyholder` spawns via SysProcAttr.Credential).

### `safe-fw` — nftables seeder

**Role:** Run once at init, applies the base ruleset, exits.

**Files:**
- `cmd/safe-fw/main.go` — reads config, builds inputs, calls `firewall.Apply`.
- `internal/firewall/ruleset.go` — `Build` returns the pure-data `Ruleset` value object.
- `internal/firewall/render.go` — `Render` emits the `nft` script form. Deterministic, testable everywhere.
- `internal/firewall/apply.go` — `Apply` shells out to `nft -f -` (this is one-shot init, not the hot path — the hot path is netlink in `safe-dns`).

**Output:** an `inet safe` table with two dynamic sets (`allowed_v4`, `allowed_v6`), one fixed set (`upstream_dns`), and an OUTPUT chain with policy `drop` plus the established/loopback/allowed-DNS/allowed-IP accept rules.

### `safe-dns` — FQDN-allowlist DNS resolver

**Role:** Listens on `127.0.0.1:53` UDP+TCP. For each query: checks the matcher → on allow, forwards to upstream and adds the resolved IPs to nftables `allowed_v4`/`allowed_v6` (via netlink, with the DNS TTL clamped to [30s, 1h]) → on deny, returns NXDOMAIN. Logs every allow/deny event to a JSONL audit log.

**Files:**
- `cmd/safe-dns/main.go` — `run()`, `dnsClientUpstream.Exchange`. Wires `Server.ErrorLog` to stderr so forward errors are visible.
- `internal/resolver/server.go` — `Server.handle` is the per-query state machine. Logs upstream/updater errors via `ErrorLog`.
- `internal/resolver/matcher.go` — `Matcher.Allows`, exact + `*.suffix` wildcard.
- `internal/resolver/ttl.go` — `ClampTTL`.
- `internal/resolver/setupdater.go` + `setupdater_linux.go` — `SetUpdater.AddMany`. Netlink via `google/nftables`. Non-Linux stub for compilation.
- `internal/resolver/audit.go` — `JSONLAuditor.Allow` / `Deny`.

**Capabilities:** runs as uid 200, has `cap_net_admin` in `CapEff` via file caps on the binary. Mode `0750 root:firewall` so the agent uid can't exec it.

### `safe-keyholder` — auth proxy

**Role:** HTTP reverse-proxy on `127.0.0.1:8443`. Reads the auth secret once from stdin at startup. Two modes:
- `apikey`: secret is a static key, injected as `Authorization: Bearer …` (or whatever `auth_header`/`auth_scheme` says).
- `oauth`: secret is the Claude Code `credentials.json` blob. Parses out access/refresh tokens. Injects current access token; refreshes via `auth_refresh_url` (default `https://console.anthropic.com/v1/oauth/token`) when within 2 minutes of expiry.

The agent's outbound request to `http://127.0.0.1:8443/...` → keyholder strips agent-supplied auth headers, inserts the real one, rewrites Host to the upstream, forwards.

**Files:**
- `cmd/safe-keyholder/main.go` — `run()`, `buildTokenSource(mode, agent, stdin)`.
- `internal/keyholder/rewrite.go` — `TokenSource` interface, static `Key`, `Rewriter.Apply`.
- `internal/keyholder/proxy.go` — `NewProxy` wraps `httputil.ReverseProxy` with a Director that calls `Rewriter.Apply`.
- `internal/keyholder/oauth.go` — `OAuthCredentials` parser, `OAuthTokenSource` with refresh.
- `internal/keyholder/bootstrap.go` — `Bootstrap(io.Reader)` reads one line into a `Key`.

**Capabilities:** uid 201, zero caps. Cannot be ptraced by uid 1000 (seccomp denial + uid mismatch).

---

## Shared internal packages

- `internal/config/` — YAML schema + loader + merger + validator.
  - `config.go` schema types (`Config`, `Agent`, `Customization`, `Resources`, `Audit`).
  - `loader.go` XDG + cwd loading.
  - `merge.go` rage-style merge (arrays append, tables merge, scalars replace).
  - `validate.go` enforces required fields and mutual-exclusion of `auth_env` / `auth_credentials_file`.

- `internal/checks/` — `safe --doctor` checks.
  - `checks.go` `Run()`, individual check functions, OAuth credentials-file readability check.
  - `docker.go` `ExecDocker` wraps `docker version` / `docker image inspect`.
  - `osenv.go` env lookup helpers + `expandHomeDir`.

- `internal/dockerrun/` — host-side docker orchestration helpers.
  - `builder.go` `BuildArgv` produces the full `docker run` argv (50+ flags).
  - `socket.go` `NewSocketDir` creates per-run dir for the keyholder Unix socket.
  - `keypipe.go` `PipeKey` writes secret to that socket once safe-init is listening.
  - `customize.go` `ExpandMounts` resolves opt-in `~/.claude/*` bind-mounts; denylist (`.credentials.json`, `projects/`, etc.) hardcoded.

- `pkg/version/` — `Version` string set by `-ldflags`. That's it.

---

## Image and CI

- `Dockerfile` — two-stage. Builder = `golang:1.25.5-bookworm` → `make build`. Runtime = `debian:forky-slim` + apt packages (nft, nodejs, git, ripgrep, etc.) + Go toolchain from go.dev + Claude Code via npm → users (firewall/keyholder/agent) → chgrp+chmod+setcap on safe-dns → hardening sweep (strip setuid, remove sudo/su) → `ENTRYPOINT ["/usr/sbin/safe-init"]`.
- `image/seccomp.json` — explicit allowlist seccomp profile. Notable denies: `ptrace`, `bpf`, `mount`, `umount`, `pivot_root`, `process_vm_readv/writev`.
- `.gitlab-ci.yml` — lint → test → build (matrix linux/darwin × amd64/arm64) → image (docker buildx push to GitLab registry).
- `Makefile` — `build`, `install` (with sudo fallback), `uninstall`, `test`, `lint`, `vet`, `fmt`, `clean`.

## Data flow at a glance

```
host: safe claude "fix bug"
  └─ loads safe.yaml, validates
  └─ creates /tmp/safe-<id>/keyholder.sock
  └─ docker run safe-runtime safe-init claude "fix bug"
       └─ safe-init (root)
            ├─ mount /proc hidepid=2  (best-effort, may skip)
            ├─ safe-fw → nftables seeded
            ├─ safe-dns as uid 200 (cap_net_admin via file cap)
            ├─ reads secret from /run/safe/keyholder.sock  ← host writes here
            ├─ safe-keyholder as uid 201, pipes secret to its stdin
            └─ exec claude as uid 1000  (no caps)
                 │
                 ├─ DNS:  127.0.0.1:53  →  safe-dns
                 │           ├─ matcher allows? →  upstream 1.1.1.1
                 │           └─ netlink: add IP to allowed_v4 with TTL
                 │
                 └─ HTTPS to api.anthropic.com:
                       agent → ANTHROPIC_BASE_URL=http://127.0.0.1:8443
                              → safe-keyholder injects real token
                                  → connect to api.anthropic.com
                                      (allowed because allowed_v4 contains the IP)
```
