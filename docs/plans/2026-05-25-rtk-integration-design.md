# RTK Integration Design

**Date:** 2026-05-25
**Status:** Approved

## What we're building

Opt-in integration of [RTK](https://github.com/rtk-ai/rtk) (Rust Token Killer) into the `safe-runtime` container image. RTK intercepts Bash command output before it reaches the LLM context, reducing token consumption 60–90% via filtering, grouping, truncation, and deduplication. It integrates with Claude Code via a `PreToolUse` hook.

## Goals

- Users can enable RTK by adding `rtk: enabled: true` to `safe.yaml` (default: true).
- RTK is pre-installed in the image; no host-side install required.
- RTK telemetry is always disabled — the container is firewalled and telemetry would fail regardless.
- Startup logs clearly state whether RTK is active so users are not surprised.
- No changes to the security model, capability set, or FQDN allowlist.

## Architecture

### Image

RTK binary is added to the `safe-runtime` image at `/usr/local/bin/rtk`, `chmod 755`, owned root. Downloaded from GitHub releases in the runtime stage via `$TARGETARCH`. Pinned to the latest release ≥ 7 days old (currently **v0.40.0**, released 2026-05-13).

### Config schema

`internal/config/config.go` gains:

```go
type RTK struct {
    Enabled *bool `yaml:"enabled"`
}
```

Added to `Config` as `RTK RTK \`yaml:"rtk"\``. `*bool` distinguishes unset from false; default-true logic applied during config merge/validate.

### `safe.yaml` template

```yaml
rtk:
  enabled: true
```

### Startup sequence

`safe-init`, after spawning `safe-keyholder` and before `syscall.Exec` of the agent:

```
[rtk.enabled=true]
  log: "rtk: enabled, telemetry disabled"
  run: rtk init -g  (as uid 1000, HOME=/home/agent, RTK_TELEMETRY_DISABLED=1)
       → writes /home/agent/.claude/settings.json  (hook)
       → writes /home/agent/.claude/RTK.md          (context injection)
  log: "rtk: hook initialized"   (or warning on non-zero exit — non-fatal)
  append RTK_TELEMETRY_DISABLED=1 to agent exec env

[rtk.enabled=false]
  log: "rtk: disabled"
```

Full updated sequence:

```
safe-init (root)
  ├─ mount /proc hidepid=2          (best-effort)
  ├─ safe-fw → nftables seeded
  ├─ safe-dns as uid 200
  ├─ read secret from /run/safe/keyholder.sock
  ├─ safe-keyholder as uid 201
  ├─ [rtk.enabled=true]
  │    ├─ log: "rtk: enabled, telemetry disabled"
  │    ├─ run: rtk init -g  (uid 1000, HOME=/home/agent)
  │    ├─ log: "rtk: hook initialized" (or "rtk: hook init failed: <err> (continuing)")
  │    └─ append RTK_TELEMETRY_DISABLED=1 to agent env
  └─ syscall.Exec agent as uid 1000
```

### Why `rtk init -g` instead of writing the hook manually

RTK owns its `settings.json` merge logic. Running `rtk init -g` as uid 1000 at each container start means:
- Correct file ownership — no `chown` step.
- Upgrade-resilient — hook format tracked by RTK itself.
- No JSON merge code to maintain in `safe-init`.
- A non-zero exit is logged as a warning and does not abort the agent.

### Network impact

None. RTK processes output locally. Telemetry is disabled via `RTK_TELEMETRY_DISABLED=1`. No new FQDN allowlist entries required.

### Security impact

None. RTK runs as uid 1000 with zero capabilities. The binary is `chmod 755` root-owned with no file caps. No new seccomp rules needed.

## File touch-points

| File | Change |
|---|---|
| `Dockerfile` | Download RTK binary for linux/amd64 + linux/arm64; verify SHA256; place at `/usr/local/bin/rtk` |
| `internal/config/config.go` | Add `RTK struct{ Enabled *bool }` to `Config` |
| `internal/config/validate.go` | Apply default-true for `RTK.Enabled` when unset |
| `cmd/safe/init.go` | Add `rtk:\n  enabled: true` to template |
| `cmd/safe-init/main.go` | Call `initRTK(cfg, agentEnv)` before exec; append env var |
| `cmd/safe-init/rtk.go` | `initRTK` — runs `rtk init -g` as uid 1000, logs result |
| `cmd/safe-init/rtk_test.go` | Unit tests (see below) |
| `docs/CONFIG.md` | Document `rtk:` block |
| `docs/CUSTOM.md` | Note: mount `~/.config/rtk/config.toml` via `customization.mounts` to tune RTK |

## Tests

| Test | Asserts |
|---|---|
| `TestRTKEnabled` | `initRTK` invokes `rtk init -g` as uid 1000; `RTK_TELEMETRY_DISABLED=1` present in returned env |
| `TestRTKDisabled` | `initRTK` not called; env var absent |
| `TestRTKInitFailure` | Non-zero exit from `rtk init -g` returns a warning log entry but no error to caller |
| `TestRTKDefaultTrue` | Config with no `rtk:` block results in `Enabled == true` after merge/validate |
