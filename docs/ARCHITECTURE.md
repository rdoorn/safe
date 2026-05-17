# SAFE — Architecture Decisions

Short log of decisions made during implementation that aren't obvious from reading the code. The original design is in `docs/plans/2026-05-15-safe-design.md`; this file captures what we changed and why once we hit reality.

## What SAFE is

A single hardened Docker container around an AI coding agent. Default-deny outbound network (nftables); FQDN allowlist enforced by an in-container DNS resolver that dynamically opens nftables rules per resolved name. LLM API auth is held by a separate uid (`keyholder`); the agent never sees the secret. `$PWD` is the only host mount.

Three principals inside the container:
- `firewall` (uid 200) — runs `safe-dns`, holds `cap_net_admin`
- `keyholder` (uid 201) — runs `safe-keyholder`, holds the LLM auth secret
- `agent` (uid 1000) — runs the actual agent and its tool subprocesses; zero capabilities

## Decisions

### 1. Debian forky base + apt-packaged nodejs
**Why:** Node 24 LTS is in Debian forky's archive; adding NodeSource would reintroduce a third-party apt repo and a `curl | bash`. The dependency-age rule (`[[feedback-dependency-age]]`) also pushes us off bleeding-edge upstream packages.
**Trade-off:** forky is testing; tag may drift. Fall back to `trixie-slim` if needed.

### 2. UIDs 200/201/1000, not 100/101/1000
**Why:** Debian forky pre-creates `users` group at gid 100, so `groupadd --system --gid 100 firewall` fails.

### 3. No `--security-opt no-new-privileges` on the container
**Why:** `no_new_privs` causes the kernel to ignore file capabilities at exec. Our `cap_net_admin+ep` on `/usr/sbin/safe-dns` is critical to the security model, so we can't enable `no_new_privs`.
**Compensating control:** `/usr/sbin/safe-dns` is mode `0750` owned by `root:firewall`, so the `agent` uid cannot exec it and therefore cannot harvest the file caps via a setuid-style attack. There are no other file-capped or setuid binaries in the image.

### 4. Netlink directly from `safe-dns`, not fork+exec of `nft`
**Why:** Linux capabilities are *per-thread*. Go's runtime schedules goroutines across multiple OS threads. When `safe-dns` raised `cap_net_admin` to its ambient set, only the thread that did the `prctl` got it. The DNS handler goroutine usually ran on a different thread, so `fork+exec(nft)` failed ~90% of the time. Replaced with `google/nftables` netlink calls; `cap_net_admin` is in `CapEff` on every thread (inherited at clone time), so netlink ops work from any goroutine.

### 5. hidepid `/proc` remount is best-effort
**Why:** `mount` requires `CAP_SYS_ADMIN`, which is too broad to grant just for PID hiding. Without hidepid the agent uid can see other uids' PIDs in `/proc`, but cannot read their `environ`/`mem`/`maps` (kernel uid checks fire regardless). Information disclosure only, not privilege gain. Users who want strict hiding can add `--cap-add SYS_ADMIN` themselves.

### 6. Setcap last, after chmod/chgrp
**Why:** `chmod`/`chgrp` strips the `security.capability` xattr in some configurations. Order in Dockerfile: chgrp firewall → chmod 0750 → setcap.

### 7. OAuth support via `auth_credentials_file`, keyholder self-refreshes
**Why:** Claude Enterprise / Claude.ai use OAuth, not static API keys. Static API key was implemented first via `auth_env`; OAuth added later as a second mutually-exclusive mode. The host CLI pipes the entire credentials JSON through the existing keyholder socket; keyholder parses it, injects the current access token, and refreshes via `console.anthropic.com` when the token nears expiry. Refreshed tokens live in keyholder memory only — not persisted back to the host file (v2).

### 8. Auth secret piped via Unix socket, never as env var
**Why:** Env vars are visible to any uid via `/proc/<pid>/environ` of the right process. Piping the secret one-shot to `safe-keyholder`'s stdin means it lives only in `keyholder`'s memory (uid 201, agent uid 1000 cannot read).

### 9. Closed agent registry (v1)
**Why:** Hardcoded list of supported agents (`claude`, `opencode`). Adding new ones requires a code change rather than a config edit. Reduces config surface area; revisit in v2.

### 10. Per-task TDD commits, override global "one commit at end" rule
**Why:** TDD red→green cycles need atomic rollback points. See `[[feedback-commit-cadence]]` in auto-memory. Conventional commit prefixes: feat / fix / docs / ci / refactor.

## Quick "what to grep when…"

| Symptom | Look at |
|---|---|
| "operation not permitted" from nft | thread-cap issue → `internal/resolver/setupdater_linux.go` |
| SERVFAIL on allowed FQDN | upstream Exchange failing → `cmd/safe-dns/main.go` `dnsClientUpstream` |
| `ANTHROPIC_API_KEY is not set` | wrong auth mode in safe.yaml → `cmd/safe/run.go` `resolveAuthSecret` |
| Agent can't reach an FQDN | allowlist missing entry → safe.yaml; also `safe-dns` audit log |
| Image build fails on gid 100 | Debian users group collision → see decision #2 |
| File caps stripped from safe-dns | Dockerfile setcap ordering → see decision #6 |
