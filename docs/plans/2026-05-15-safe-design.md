# SAFE — Sandboxed Agent For Engineering

**Status:** Design — approved 2026-05-15
**Authors:** rdoorn

## Summary

SAFE is a single-container sandbox for running AI coding agents (Claude Code, opencode, …) with cilium-style FQDN filtering, secret containment, and a curated tool set, in the simplest usage shape possible: `safe claude [args...]` drops you into the agent with `$PWD` as the workspace.

It sits in the same family as the existing tools:

| Tool | Role |
|---|---|
| RAGE | Userspace MITM proxy wrapping a single agent process |
| CAGE | Per-project container orchestrator with Forgejo as review gate |
| Argus | Host-side eBPF observer/enforcer |
| **SAFE** | **Single container, single command, default-deny network, minimal moving parts** |

SAFE is intentionally simpler than CAGE+RAGE+Argus combined. It is not a replacement for them — it is a lighter alternative for the common case of "I just want to run an agent safely on my Mac without thinking about it."

## Goals

- **Single command:** `safe claude [args...]` works the same as `claude [args...]`, with `$PWD` mounted as the workspace.
- **Single container:** no second pod, no host-side daemon, no privileged sidecar.
- **Default-deny network:** the agent can only reach hosts on an explicit FQDN allowlist. Raw IPs, DNS exfil, UDP — all blocked by construction.
- **Secret containment:** the agent process cannot read the Anthropic API key or any host credential.
- **Ephemeral by default:** each invocation = fresh container. No long-lived state to manage.
- **macOS support:** runs on Docker Desktop / Colima / OrbStack without `--privileged` or custom kernel modules.
- **Agent-agnostic:** Claude Code is the first agent, but the design supports adding others without changing the security model.

## Non-goals

- Replacing CAGE, RAGE, or Argus.
- Path-level access control on individual API calls (use RAGE if you need that).
- LLM request/response auditing (deferred to v2 or solved with RAGE in front of the keyholder).
- True kernel-level eBPF enforcement (use Argus if you need that).
- Per-project named environments à la CAGE (`safe env create …`).
- Forgejo-style review UI (use CAGE if you need that).
- Custom user-defined agents in v1 (the agent registry is closed).

## Architecture

### Layered defences

```
host
 │  safe CLI (Go binary)
 │   ├─ load + merge config (~/.config/safe/safe.yaml + ./safe.yaml)
 │   ├─ docker run --cap-drop ALL --cap-add NET_ADMIN
 │   │             --security-opt seccomp=… --security-opt no-new-privileges
 │   │             --read-only --tmpfs … --pids-limit … --memory …
 │   │             -v $PWD:/workspace
 │   │             -v /tmp/safe-<id>:/run/safe
 │   └─ pipe ANTHROPIC_API_KEY into keyholder.sock, then close
 │
 └── safe-runtime container (one PID 1, three user accounts)
      │
      ├─ safe-init  (root, exits after handoff)
      │   ├─ mount /proc with hidepid=2
      │   ├─ start safe-fw     (root → user firewall via file caps)
      │   ├─ start safe-dns    (user firewall, cap_net_admin file cap)
      │   ├─ start safe-keyholder (user keyholder, no caps)
      │   ├─ read API key from /run/safe/keyholder.sock, hand to keyholder
      │   └─ exec agent as user agent (no caps)
      │
      ├─ nftables OUTPUT default DROP
      │   ├─ ACCEPT loopback
      │   ├─ ACCEPT UDP/53 → 127.0.0.1 (any user)
      │   ├─ ACCEPT UDP/53 → upstream resolver (only from user firewall)
      │   └─ <dynamic IP rules added by safe-dns, expire on DNS TTL>
      │
      └─ Users
          uid 100 firewall   — safe-dns, holds NET_ADMIN via file cap
          uid 101 keyholder  — safe-keyholder, holds the real API key in memory
          uid 1000 agent     — the agent + every tool subprocess; no caps
```

### Why this shape

- **nftables in default-drop** gives the same property as Cilium's FQDN policy: nothing leaves unless explicitly allowed.
- **DNS as the only gate** keeps the policy human-readable (hostnames, not IPs) and matches how every real workload reaches the internet.
- **Keyholder + uid separation** means the credential and the agent live in different security domains. Even if the agent is fully compromised at the application layer, it cannot read the key.
- **No `--privileged`** keeps SAFE viable on macOS Docker without kernel-version coupling.

## Components

### safe (host CLI, Go)

Cobra-based binary, single static build. Responsibilities:

- Resolve agent name from the built-in registry.
- Load and merge config (`~/.config/safe/safe.yaml` + `./safe.yaml`, rage-style merge).
- Validate config (schema, required allowlist entries, agent registry hits).
- Prepare per-run socket directory `/tmp/safe-<id>/`.
- Build the `docker run` command with all hardening flags.
- Pipe the API key into the keyholder socket exactly once at startup.
- Forward stdin/stdout/stderr to the container TTY.
- Propagate the agent's exit code.

Subcommands:

```
safe <agent> [agent args...]   # default: run the named agent
safe --shell                   # bash inside the sandbox (no agent)
safe --doctor                  # pre-flight checks
safe --pull                    # pull/update safe-runtime image
safe --print-config            # show merged config
safe --version
```

### safe-runtime (container image)

Debian-slim or Alpine base (TBD during implementation; favour Debian-slim for `nft` and toolchain availability). Layered:

- **Base layer:** OS + minimal utilities.
- **Tool layer:** `git`, `gh`, `ripgrep`, `fd`, `jq`, `curl`, `wget`, `make`, `go`, `python` (with `pip`/`venv`), `node` (with `npm`/`yarn`), `tini`-equivalent (handled by `safe-init`).
- **Agent layer:** Claude Code (`npm i -g @anthropic-ai/claude-code` or equivalent), pinned version.
- **SAFE layer:** `safe-init`, `safe-fw`, `safe-dns`, `safe-keyholder` binaries; default nftables seed ruleset; seccomp profile at `/etc/safe/seccomp.json`.
- **Users:** `firewall` (100), `keyholder` (101), `agent` (1000), home dirs preconfigured.
- **File caps:** `setcap cap_net_admin+ep /usr/sbin/safe-dns` at build time.
- **Read-only-friendly:** no service runs that requires writable rootfs.

Image is published to a container registry as `ghcr.io/<org>/safe-runtime:<tag>`.

### safe-init

PID 1 in the container. Single Go binary. Responsibilities:

1. Mount `/proc` with `hidepid=2,gid=<firewall>` so non-firewall users can't see other users' processes or environments.
2. Read `/etc/safe/config.yaml` (injected by the host CLI as a Docker tmpfs/secret).
3. Spawn `safe-fw` as root briefly to seed nftables rules, then it exits.
4. Spawn `safe-dns` as user `firewall`. `safe-dns` keeps `cap_net_admin` via file cap (effective + permitted).
5. Spawn `safe-keyholder` as user `keyholder`.
6. Read API key from `/run/safe/keyholder.sock`, write it to keyholder's stdin once, close the pipe. Wipe local buffer.
7. Drop to user `agent` with `prctl(PR_SET_NO_NEW_PRIVS, 1)`, then `exec` the agent with `ANTHROPIC_BASE_URL=http://127.0.0.1:8443` and `ANTHROPIC_API_KEY=dummy`.
8. Forward signals (SIGINT/SIGTERM) to the agent. Reap zombies (standard tini behaviour).
9. On agent exit, exit with the same code.

### safe-fw

Tiny Go program. Run once at init, exits. Loads the base nftables ruleset:

```
table inet safe {
  set allowed_v4 { type ipv4_addr; flags timeout, dynamic; }
  set allowed_v6 { type ipv6_addr; flags timeout, dynamic; }

  chain output {
    type filter hook output priority filter; policy drop;

    ct state established,related accept
    oif "lo" accept
    udp dport 53 ip daddr 127.0.0.1 accept
    meta skuid 100 udp dport 53 ip daddr @upstream_dns accept
    ip daddr @allowed_v4 accept
    ip6 daddr @allowed_v6 accept
    log prefix "safe-drop: " counter
  }
}
```

The `@upstream_dns` set is seeded from the resolver list in `safe.yaml` (default: `1.1.1.1`, `1.0.0.1`). The dynamic sets `@allowed_v4`/`@allowed_v6` are populated by `safe-dns` with per-entry timeouts.

### safe-dns

The heart of SAFE. Go DNS server using `miekg/dns`. Runs as user `firewall`. Responsibilities:

- Listen on `127.0.0.1:53` (UDP and TCP).
- On query: look up the QNAME (case-insensitive, suffix match for `*.example.com` patterns) against the in-memory FQDN allowlist.
  - **Match:** forward to one of the upstream resolvers. On successful response, extract each A/AAAA record, add to `@allowed_v4`/`@allowed_v6` with `timeout = min(record_ttl, max_ttl_cap)`, then return the response to the client.
  - **No match:** return `NXDOMAIN`. Log a structured audit entry.
- Refresh rule timeouts on subsequent queries for the same name (keeps long-lived connections alive).
- Cap minimum TTL at 30s (some CDNs use 0/1s TTLs that would churn rules).
- Cap maximum TTL at 1h (so a short-lived allowance can't outlive a session).
- Expose a Unix-socket admin endpoint at `/run/safe/dns.sock` for `safe --print-config`-style introspection (read-only). Accessible only to user `firewall` and root.

### safe-keyholder

Tiny Go HTTP server. Runs as user `keyholder`. Responsibilities:

- Read the real API key from stdin once at startup, store in memory, discard the pipe.
- Listen on `127.0.0.1:8443` (HTTP, not HTTPS — it's a localhost loopback).
- For each incoming request:
  - Read the request headers and body.
  - Strip any `Authorization`, `x-api-key` header from the request.
  - Substitute with `Authorization: Bearer <real_key>` (or `x-api-key`, depending on the agent's auth style — looked up per-agent in the registry).
  - Replace the `Host` header with the agent's configured upstream host (e.g. `api.anthropic.com`).
  - Dial the upstream (TLS) over the configured base URL. The dial triggers a DNS lookup against `safe-dns`, which installs the appropriate nftables rule.
  - Stream the response back to the agent.
- No persistence, no logging of bodies. Optionally a counter for requests for `--doctor`.
- If the upstream returns a 401/403 with a known "bad key" body, log a one-line audit message ("upstream rejected the key — check ANTHROPIC_API_KEY on the host") and return as-is.

## CLI shape

Drop-in agent wrapper. The agent and its args are forwarded verbatim:

```
safe claude                              → claude
safe claude --resume                     → claude --resume
safe claude --dangerously-skip-permissions  → claude --dangerously-skip-permissions
safe opencode build                      → opencode build
```

SAFE-specific flags use `--safe-*` to avoid collisions, e.g. `safe --safe-config /tmp/alt.yaml claude`. (Most won't need this — global flags like `--shell`, `--doctor`, `--pull` come *before* the agent name.)

## Container `docker run` invocation

The exact flags the host CLI assembles:

```
docker run --rm -i [-t if stdin is a tty] \
  --name safe-<random> \
  --hostname safe \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --security-opt seccomp=<embedded profile> \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --tmpfs /run:rw,nosuid,nodev,noexec,size=64m \
  --tmpfs /home/agent:rw,nosuid,nodev,size=512m \
  --pids-limit 256 \
  --memory 4g \
  --memory-swap 4g \
  --network bridge \
  --dns 127.0.0.1 \
  -v "$PWD":/workspace \
  -v safe-cache-<project-hash>:/home/agent/.cache \
  -v /tmp/safe-<id>:/run/safe \
  <conditional opt-in mounts: skills, commands, claudemd, …> \
  --env-file /dev/null \
  -e TERM -e LANG -e TZ \
  ghcr.io/<org>/safe-runtime:<tag> \
  safe-init <agent> <args...>
```

Seccomp profile = Docker default + additional denials: `ptrace`, `bpf`, `mount`, `umount`, `umount2`, `pivot_root`, `userfaultfd`, `kexec_load`, `init_module`, `delete_module`, `process_vm_readv`, `process_vm_writev`.

## Data flow

### Cold start

1. User runs `safe claude "fix the auth bug"` in a project directory.
2. Host CLI: resolve agent → load config → validate → check `ANTHROPIC_API_KEY` exists on host → assemble `docker run` → fork it.
3. Inside: `safe-init` runs as root, mounts `/proc hidepid=2`, starts `safe-fw` (which seeds nftables and exits), starts `safe-dns` (firewall user, cap_net_admin), starts `safe-keyholder` (keyholder user).
4. Host writes the API key once into `/tmp/safe-<id>/keyholder.sock` and closes. `safe-init` forwards it into keyholder's stdin pipe, then closes.
5. `safe-init` drops to user `agent`, sets `no_new_privs`, `exec`s `claude "fix the auth bug"` with `ANTHROPIC_BASE_URL=http://127.0.0.1:8443`.

### Outbound to an allowed FQDN

1. Agent (or `keyholder` on agent's behalf) dials `api.anthropic.com:443`.
2. libc → `127.0.0.1:53` (safe-dns).
3. safe-dns: matches allowlist, forwards to `1.1.1.1`. Note: this upstream DNS query passes nftables because of the `meta skuid 100 udp dport 53 ip daddr @upstream_dns accept` rule (firewall is uid 100).
4. Upstream returns IPs with TTL.
5. safe-dns adds IPs to `@allowed_v4` set with `timeout = min(ttl, 1h)`, max(30s).
6. safe-dns returns the response to the caller.
7. Caller's TCP SYN to the IP traverses OUTPUT: matches `ip daddr @allowed_v4 accept` → connection succeeds.

### Outbound to a denied FQDN

1. Agent runs `curl https://evil.com`.
2. libc → 127.0.0.1:53 (safe-dns).
3. safe-dns: no allowlist match → return `NXDOMAIN`. Audit log: `denied fqdn=evil.com uid=1000`.
4. curl reports DNS failure.

### Outbound to a raw IP

1. Agent runs `curl https://1.2.3.4`.
2. No DNS query happens; libc dials directly.
3. nftables OUTPUT: no rule matches (1.2.3.4 not in `@allowed_v4`) → packet dropped.
4. curl times out connecting.
5. The drop counter increments on the `log` rule; the nft log entry goes to dmesg-equivalent inside the container, harvested by safe-dns and written to the audit log.

### Bypass attempts

- **DNS-over-HTTPS to Cloudflare:** the TCP SYN to `1.1.1.1:443` would need `1.1.1.1` in `@allowed_v4`. It is not (the DNS allow rule is UDP/53 only, scoped to uid 100). Dropped.
- **Raw IP through a proxy on the host:** the agent has no route to the host (`--network bridge`, host loopback unreachable from container).
- **Reading keyholder's key from `/proc`:** `hidepid=2` hides other users' `/proc` entries from `agent`. Even with the PID known, `/proc/<keyholder>/environ` and `/proc/<keyholder>/mem` require either same-uid or `CAP_SYS_PTRACE`, neither of which `agent` has. `ptrace` is also denied by seccomp.
- **Spawning a setuid binary:** none exist in the image (build-time `find / -perm /4000 -exec chmod a-s {} \;`). `no_new_privs` prevents acquiring any new caps even if one did.

## Configuration

### Files

```
~/.config/safe/safe.yaml        # global
./safe.yaml                     # per-project, merged on top
```

Merge rules (rage-compatible):
- Arrays append (extend, don't replace).
- Tables merge recursively.
- Scalars in the per-project file override globals.

### Schema (initial)

```yaml
agents:
  claude:
    image: ghcr.io/<org>/safe-runtime:0.1.0
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url_env: ANTHROPIC_BASE_URL
    base_url: https://api.anthropic.com
    auth_header: Authorization     # or x-api-key per agent
    auth_scheme: Bearer            # or "" for x-api-key style
    locked_tools: [Read, Write, Edit, Bash, Glob, Grep, NotebookEdit]
    env:
      DISABLE_TELEMETRY: "1"
      CLAUDE_CODE_DISABLE_AUTOUPDATER: "1"
      CLAUDE_CODE_DISABLE_BACKGROUND_TASKS: "1"
    customization:
      skills:     true
      commands:   true
      claudemd:   true
      settings:   false
      statusline: false
      hooks:      false
      plugins:    false

  opencode:
    image: ghcr.io/<org>/safe-runtime:0.1.0
    entrypoint: opencode
    auth_env: OPENAI_API_KEY
    # …

allowlist:
  - api.anthropic.com
  - registry.npmjs.org
  - pypi.org
  - files.pythonhosted.org
  - proxy.golang.org
  - sum.golang.org
  - deb.debian.org
  - security.debian.org
  # NOTE: github.com deliberately NOT here. No push from inside SAFE.

upstream_dns:
  - 1.1.1.1
  - 1.0.0.1

mounts: []                    # opt-in extras only, default empty
env_passthrough: [TERM, LANG, TZ]

resources:
  memory: 4g
  pids: 256

audit:
  enabled: true
  host_path: ~/.local/share/safe/audit.log
```

### Validation

- `allowlist` entries must be valid DNS names or `*.<name>` patterns; no IPs.
- `agents.<name>.image` must be a parseable image reference.
- `customization` flags must reference real subdirs under `~/.claude/`.
- Locked tools must be a non-empty subset of the known Claude Code tool names; unknown tool names are a hard error.
- Required FQDNs for the active agent (e.g. `api.anthropic.com` for `claude`) must be present in the merged allowlist or SAFE refuses to start with a clear message.

## User customization

### Runtime customization (no rebuild)

Read-only opt-in subdir mounts under `~/.claude/`:

| Subdir | Default | Mounted at | Notes |
|---|---|---|---|
| `skills/` | on | `/home/agent/.claude/skills:ro` | markdown skills |
| `commands/` | on | `/home/agent/.claude/commands:ro` | slash commands |
| `CLAUDE.md` | on | `/home/agent/.claude/CLAUDE.md:ro` | global memory |
| `settings.json` | off | `/home/agent/.claude/settings.json:ro` | may reference scripts |
| `statusline.sh` | off | `/home/agent/.claude/statusline.sh:ro` | executable, runs as `agent` |
| `hooks/` | off | `/home/agent/.claude/hooks:ro` | executables, run as `agent` |
| `plugins/` | off | `/home/agent/.claude/plugins:ro` | may include scripts |

Hardcoded denylist (never mounted regardless of config):
- `.credentials.json`
- `projects/`
- `.claude.json`
- anything matching `**/.git/` inside `.claude`

Project-local `.claude/` is automatically available because `$PWD` is mounted; no opt-in needed.

### Image customization (rebuild required)

Users build their own image FROM the official one:

```dockerfile
FROM ghcr.io/<org>/safe-runtime:0.1.0
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      terraform postgresql-client \
 && rm -rf /var/lib/apt/lists/*
USER agent
```

Then point SAFE at it:

```yaml
agents:
  claude:
    image: myorg/safe-runtime-custom:latest
```

No `safe bake` command in v1 — `docker build` is the universal interface.

## Error handling

- **Docker missing / not running:** `safe --doctor` enumerates checks. Plain `safe <agent>` runs the same checks and fails fast with the same messages.
- **Image not present:** auto-pull on first run if reachable; otherwise instruct the user.
- **Required env var missing:** hard error before `docker run`.
- **Invalid config:** schema validation at load time; error names file, key, and problem.
- **Init failure inside container:** `safe-init` writes a structured stderr line and exits non-zero.
- **Agent crash:** SAFE returns the agent's exit code, no retry.
- **DNS denials are not errors**, they're audit events. The agent sees them as resolution failures.

## Testing

### Unit (Go)

- Config loading + merging (per-table, per-array, per-scalar cases).
- FQDN matching (exact + `*.example.com` suffix; case insensitivity).
- TTL bookkeeping in safe-dns (clamping, refresh on re-query).
- nftables rule serialisation against golden output.
- Keyholder header substitution (auth, host, body passthrough).

### Integration (CI, real container)

- Allowed FQDN: `curl -fsS https://api.anthropic.com/v1/messages` returns an upstream auth error → proves the path works end-to-end.
- Disallowed FQDN: `host evil.com` → NXDOMAIN.
- Raw IP: `curl https://1.1.1.1` → timeout / connection refused.
- DNS exfil: `dig @8.8.8.8 evil.com` → blocked at nft.
- Keyholder isolation: `gdb -p $(pgrep keyholder)` → permission denied. `cat /proc/<keyholder>/environ` → permission denied.
- Hidepid: `ls /proc | grep -c <keyholder_uid>` → 0 from agent's perspective.
- Setuid: `find / -perm /4000` → empty.
- File caps: `getcap /usr/sbin/safe-dns` → `cap_net_admin+ep`.

### Manual scenarios

`docs/TEST.md` (to be written) — prompts pasted into the agent to verify:
- "Try to fetch evil.com" → agent reports failure.
- "Find my AWS credentials" → no credentials are mounted to find.
- "Echo the value of ANTHROPIC_API_KEY" → empty / dummy.
- "Push my work to GitHub" → fails (no creds, github.com not allowlisted).

## Open questions for implementation

- **DNS TTL clamp values.** Default 30s min / 1h max is a guess. Validate against real CDN behaviour during dogfooding.
- **Resolver upstream selection.** Hardcoded `1.1.1.1` for now; consider letting the host's resolver list pass through (with care — must allow only via `firewall` uid).
- **Bridge network DNS leak.** Confirm Docker doesn't inject its own DNS that would bypass our resolver. Tested with `--dns 127.0.0.1` set explicitly.
- **macOS Docker Desktop kernel.** Confirm nftables is built into the LinuxKit VM (it has been for several years, but verify per major Docker version).
- **Image size target.** 500MB feels reasonable for a base with Go + Python + Node toolchains. Track during build.
- **First-class observability.** `--audit-tail` or web UI for blocked traffic could be a v2 ergonomic improvement.

## Out of scope for v1, candidate v2 work

- LLM request/response audit log (route keyholder through RAGE).
- Per-agent custom registries from the host config.
- Agent-restricted MCP server allowlist (parallel to FQDN allowlist).
- `safe bake` convenience command for tool addition.
- Web UI / dashboard for FQDN allowlist editing and audit viewing.
- Argus integration for kernel-level visibility on hosts where it's available.
