# SAFE Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build SAFE v1 — a single-container sandbox for AI coding agents with FQDN-anchored default-deny networking, secret containment via a keyholder proxy, and a `safe <agent> [args...]` drop-in CLI.

**Architecture:** Go host CLI (`safe`) shells out to `docker run` with strict hardening flags (cap-drop ALL + NET_ADMIN, seccomp, read-only rootfs, no env passthrough). Inside the container, a Go PID-1 (`safe-init`) brings up three Go daemons: `safe-fw` (nftables seeder), `safe-dns` (FQDN-allowlist resolver that dynamically installs nftables rules), and `safe-keyholder` (HTTP proxy that injects the LLM API auth header, isolated from the agent by uid).

**Tech Stack:**
- **Language:** Go 1.22+ everywhere.
- **CLI framework:** `github.com/spf13/cobra`.
- **YAML:** `gopkg.in/yaml.v3`.
- **DNS:** `github.com/miekg/dns`.
- **nftables:** `github.com/google/nftables`.
- **Testing:** stdlib `testing` + `github.com/stretchr/testify/require`.
- **Lint:** `golangci-lint` (fmt, vet, staticcheck, errcheck, gocyclo).
- **CI:** GitLab CI (matches RAGE/CAGE/Argus).
- **Container base:** `debian:bookworm-slim`.

**Design source of truth:** `docs/plans/2026-05-15-safe-design.md`.

---

## Milestone 0 — Repo scaffolding

**Goal:** Empty repo → buildable Go workspace with CI, lint, and a no-op `safe` binary.

### Task 0.1: Initialise Go module + base files

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `LICENSE` (MIT or Apache-2.0, match RAGE)
- Create: `README.md` (one-paragraph stub)
- Create: `cmd/safe/main.go`
- Create: `cmd/safe-init/main.go`
- Create: `cmd/safe-fw/main.go`
- Create: `cmd/safe-dns/main.go`
- Create: `cmd/safe-keyholder/main.go`

**Step 1:** `go mod init github.com/<org>/safe` (replace `<org>` once decided).
**Step 2:** Create each `main.go` with a stub `func main() { fmt.Println("<binary>") }`.
**Step 3:** `go build ./...` — must succeed.
**Step 4:** Commit: `feat: scaffold Go module and binary entry points`.

### Task 0.2: Makefile

**Files:** Create `Makefile`.

```make
.PHONY: build test lint vet fmt clean image

BINARIES := safe safe-init safe-fw safe-dns safe-keyholder
BIN_DIR  := bin

build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do go build -o $(BIN_DIR)/$$b ./cmd/$$b; done

test:
	go test ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN_DIR)
```

**Step 1:** Run `make build` — all five binaries land in `bin/`.
**Step 2:** Run `make vet` — must pass.
**Step 3:** Commit: `feat: add Makefile`.

### Task 0.3: golangci-lint config

**Files:** Create `.golangci.yml`.

Enable: `gofmt`, `govet`, `staticcheck`, `errcheck`, `gocyclo` (max 15), `revive`, `gosec`, `misspell`. Disable `varnamelen`.

**Step 1:** Run `golangci-lint run ./...` — must pass (empty stubs).
**Step 2:** Commit: `feat: add golangci-lint config`.

### Task 0.4: GitLab CI skeleton

**Files:** Create `.gitlab-ci.yml`.

Stages: `lint`, `test`, `build`, `image`, `release`. For now wire up only `lint`, `test`, `build` using a `golang:1.22` image. Mirror CAGE's structure for consistency.

**Step 1:** Push to a feature branch, verify pipeline runs green.
**Step 2:** Commit: `ci: add GitLab CI skeleton`.

### Task 0.5: Internal package layout

**Files:** Create empty directories with a placeholder `.gitkeep` so layout is committed:
- `internal/config/`
- `internal/firewall/`
- `internal/resolver/`
- `internal/keyholder/`
- `internal/initd/` (PID-1 logic)
- `internal/dockerrun/`
- `internal/agents/` (the agent registry)
- `pkg/version/`

**Step 1:** Commit: `feat: add internal package layout`.

---

## Milestone 1 — Host CLI core

**Goal:** `safe --print-config` and `safe --doctor` work against a real `safe.yaml`. No Docker yet.

### Task 1.1: Config schema

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Step 1: Write the failing test.**

```go
func TestParseMinimalConfig(t *testing.T) {
    src := `
agents:
  claude:
    image: ghcr.io/example/safe-runtime:0.1.0
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
allowlist:
  - api.anthropic.com
upstream_dns:
  - 1.1.1.1
`
    cfg, err := config.Parse([]byte(src))
    require.NoError(t, err)
    require.Equal(t, "claude", cfg.Agents["claude"].Entrypoint)
    require.Equal(t, []string{"api.anthropic.com"}, cfg.Allowlist)
}
```

**Step 2:** Run `go test ./internal/config/...` — expect FAIL (package empty).
**Step 3: Implement the minimum to pass.**

```go
package config

import "gopkg.in/yaml.v3"

type Config struct {
    Agents       map[string]Agent  `yaml:"agents"`
    Allowlist    []string          `yaml:"allowlist"`
    UpstreamDNS  []string          `yaml:"upstream_dns"`
    Mounts       []string          `yaml:"mounts"`
    EnvPassthrough []string        `yaml:"env_passthrough"`
    Resources    Resources         `yaml:"resources"`
    Audit        Audit             `yaml:"audit"`
}

type Agent struct {
    Image        string            `yaml:"image"`
    Entrypoint   string            `yaml:"entrypoint"`
    AuthEnv      string            `yaml:"auth_env"`
    BaseURLEnv   string            `yaml:"base_url_env"`
    BaseURL      string            `yaml:"base_url"`
    AuthHeader   string            `yaml:"auth_header"`
    AuthScheme   string            `yaml:"auth_scheme"`
    LockedTools  []string          `yaml:"locked_tools"`
    Env          map[string]string `yaml:"env"`
    Customization Customization    `yaml:"customization"`
}

type Customization struct {
    Skills, Commands, ClaudeMD, Settings, Statusline, Hooks, Plugins bool
}

type Resources struct {
    Memory string `yaml:"memory"`
    PIDs   int    `yaml:"pids"`
}

type Audit struct {
    Enabled  bool   `yaml:"enabled"`
    HostPath string `yaml:"host_path"`
}

func Parse(data []byte) (*Config, error) {
    var c Config
    return &c, yaml.Unmarshal(data, &c)
}
```

**Step 4:** Test passes.
**Step 5:** Commit: `feat(config): add YAML schema and parser`.

### Task 1.2: Config loader (XDG + cwd)

**Files:**
- Create: `internal/config/loader.go`
- Create: `internal/config/loader_test.go`

**Step 1: Failing test.** Verify `Load()` reads `$XDG_CONFIG_HOME/safe/safe.yaml` then merges `./safe.yaml` on top.
**Step 2:** Implement `Load(cwd string) (*Config, error)` using `os.UserConfigDir()` then the cwd path.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(config): load XDG + cwd configs`.

### Task 1.3: Config merger

**Files:**
- Create: `internal/config/merge.go`
- Create: `internal/config/merge_test.go`

**Merge rules:** arrays append, tables merge recursively, scalars replace.

**Step 1: Failing tests.** Three table-driven cases — array append, scalar override, nested table merge.
**Step 2:** Implement `Merge(base, overlay *Config) *Config` (no reflection; explicit per-field for clarity).
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(config): rage-style merge semantics`.

### Task 1.4: Config validator

**Files:**
- Create: `internal/config/validate.go`
- Create: `internal/config/validate_test.go`

**Validation rules** (from design):
- `allowlist` entries match `^([a-z0-9-]+\.)+[a-z]{2,}$` or `^\*\.([a-z0-9-]+\.)+[a-z]{2,}$`.
- Every `agents.<name>.image` is a parseable image ref (use stdlib regex).
- `agents.<name>.locked_tools` are a non-empty subset of a known tool set (hardcoded list of Claude Code tool names).
- For an agent named on the CLI, its `BaseURL`'s host MUST appear in `allowlist`. If not, validation fails with a clear message.

**Step 1:** Failing tests, one per rule.
**Step 2:** Implement `Validate(c *Config, agentName string) error`.
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(config): validation`.

### Task 1.5: Cobra root command + version

**Files:**
- Modify: `cmd/safe/main.go`
- Create: `pkg/version/version.go` (with `var Version = "dev"` set via `-ldflags`).

**Step 1:** Wire up cobra. Persistent `--config` flag (defaults empty → use XDG). `safe --version` prints the version.
**Step 2:** `make build && bin/safe --version` → prints `safe dev`.
**Step 3:** Commit: `feat(cli): cobra root command`.

### Task 1.6: `safe --print-config`

**Files:**
- Modify: `cmd/safe/main.go`
- Create: `cmd/safe/printconfig.go`
- Create: `cmd/safe/printconfig_test.go`

**Step 1:** Failing test — given a temp dir with a fixture config, `safe --print-config` writes the merged YAML to stdout.
**Step 2:** Implement using `yaml.Marshal` of the merged config.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(cli): --print-config`.

### Task 1.7: `safe --doctor`

**Files:**
- Create: `cmd/safe/doctor.go`
- Create: `internal/checks/checks.go`
- Create: `internal/checks/checks_test.go`

**Checks (each returns ok/err + a one-line description):**
- Docker reachable (`docker version --format '{{.Server.Version}}'` exits 0).
- Image present (`docker image inspect <image>` exits 0).
- Config valid (`config.Load` + `config.Validate` succeed).
- Required env var present for default agent.

**Step 1:** Failing tests with `os/exec` mocked via an interface.
**Step 2:** Implement.
**Step 3:** Tests pass.
**Step 4:** Manual smoke: `bin/safe --doctor` on a real machine.
**Step 5:** Commit: `feat(cli): --doctor preflight checks`.

---

## Milestone 2 — `safe-fw` (nftables seeder)

**Goal:** A binary that, given the merged config, applies the base nftables ruleset and exits.

### Task 2.1: Ruleset builder

**Files:**
- Create: `internal/firewall/ruleset.go`
- Create: `internal/firewall/ruleset_test.go`

**Step 1: Failing test.** Given `upstream_dns: [1.1.1.1]` and `firewallUID: 100`, produce a `*nftables.Conn` script (or a pure-data representation) with the rules described in design §safe-fw.
**Step 2:** Implement using `google/nftables`. Return a value object that can be tested without netlink.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(firewall): build base ruleset`.

### Task 2.2: Apply via netlink

**Files:**
- Create: `internal/firewall/apply.go`
- Create: `internal/firewall/apply_test.go` (build tag `integration`).

**Step 1:** Behind a build tag, an integration test that runs inside a Linux network namespace, applies the ruleset, and verifies via `nft list ruleset`.
**Step 2:** Implement `Apply(ctx, rs) error`.
**Step 3:** Integration test passes (run in CI on Linux only).
**Step 4:** Commit: `feat(firewall): netlink apply`.

### Task 2.3: `safe-fw` CLI

**Files:**
- Modify: `cmd/safe-fw/main.go`.

Reads `/etc/safe/config.yaml`, builds the ruleset, applies it, exits 0.

**Step 1:** Manual smoke: build inside container, run, `nft list ruleset` shows expected output.
**Step 2:** Commit: `feat(safe-fw): cli entry`.

---

## Milestone 3 — `safe-dns` (resolver + dynamic firewall)

**Goal:** A DNS server listening on `127.0.0.1:53` that allowlists hostnames, forwards them upstream, and installs nftables rules per response.

### Task 3.1: FQDN matcher

**Files:**
- Create: `internal/resolver/matcher.go`
- Create: `internal/resolver/matcher_test.go`

**Step 1: Failing tests.** Cases: exact match (case-insensitive), suffix `*.example.com`, no match, root domain, IDN handling deferred.
**Step 2:** Implement `Matcher` with `Add(pattern)` and `Allows(name) bool`.
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(resolver): FQDN matcher`.

### Task 3.2: TTL clamper

**Files:**
- Create: `internal/resolver/ttl.go`
- Create: `internal/resolver/ttl_test.go`

**Logic:** `clamp(ttl) = max(min(ttl, maxCap), minCap)` with defaults `minCap=30s`, `maxCap=1h`.

**Step 1:** Failing tests (below min, in range, above max, zero, MaxUint32).
**Step 2:** Implement.
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(resolver): TTL clamping`.

### Task 3.3: nftables set updater

**Files:**
- Create: `internal/resolver/setupdater.go`
- Create: `internal/resolver/setupdater_test.go` (with build tag `integration`).

**Step 1:** Behind the integration tag, a test that creates `inet safe allowed_v4` with `dynamic timeout` and asserts `AddIP(addr, ttl)` makes it visible via `nft list set inet safe allowed_v4`.
**Step 2:** Implement `SetUpdater` wrapping `nftables.Conn`.
**Step 3:** Integration test passes.
**Step 4:** Commit: `feat(resolver): dynamic nftables set updates`.

### Task 3.4: DNS server skeleton

**Files:**
- Create: `internal/resolver/server.go`
- Create: `internal/resolver/server_test.go`

**Step 1: Failing test.** Start the server on an ephemeral port, query for an allowlisted name, assert a response with the right answer comes back. Use a stub upstream client.
**Step 2:** Implement using `miekg/dns`. Single concurrent path: receive → match → forward → install rule → reply.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(resolver): DNS server core`.

### Task 3.5: Denials return NXDOMAIN

**Files:** extend `server.go` + tests.

**Step 1:** Failing test — disallowed name returns `NXDOMAIN` and no upstream call is made.
**Step 2:** Add the gate before the upstream call.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(resolver): deny → NXDOMAIN`.

### Task 3.6: Audit log writer

**Files:**
- Create: `internal/resolver/audit.go`
- Create: `internal/resolver/audit_test.go`

**Format:** one JSON object per line. Fields: `ts`, `event` (`allow`/`deny`), `fqdn`, `client_addr`, `ttl` (allow only).

**Step 1:** Failing test against an `io.Writer` buffer.
**Step 2:** Implement.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(resolver): structured audit log`.

### Task 3.7: `safe-dns` CLI

**Files:** Modify `cmd/safe-dns/main.go`.

Reads `/etc/safe/config.yaml`, opens nftables, builds matcher from `allowlist`, runs the DNS server. Logs to `/var/log/safe/audit.log` (mounted on a tmpfs that we shadow with a bind to a host volume at container start, see Milestone 7).

**Step 1:** Manual smoke inside a container: `dig @127.0.0.1 api.anthropic.com` returns answer; `dig @127.0.0.1 evil.com` returns NXDOMAIN.
**Step 2:** Commit: `feat(safe-dns): cli entry`.

---

## Milestone 4 — `safe-keyholder`

**Goal:** HTTP proxy on `127.0.0.1:8443` that injects the LLM API key.

### Task 4.1: Header substitution

**Files:**
- Create: `internal/keyholder/rewrite.go`
- Create: `internal/keyholder/rewrite_test.go`

**Step 1: Failing test.** Given an `http.Request` with `Authorization: dummy` and `Host: 127.0.0.1:8443`, after `Rewrite(req, agent)` the request has `Authorization: Bearer <key>` and `Host: api.anthropic.com`, body unchanged.
**Step 2:** Implement.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(keyholder): header rewrite`.

### Task 4.2: Reverse proxy

**Files:**
- Create: `internal/keyholder/proxy.go`
- Create: `internal/keyholder/proxy_test.go`

**Step 1: Failing test.** Spin up a stub upstream `httptest.Server`. Configure keyholder to target it. Send a request to the proxy. Assert upstream saw the rewritten headers.
**Step 2:** Implement using `httputil.ReverseProxy` with a custom `Director`.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(keyholder): reverse proxy`.

### Task 4.3: Key bootstrap (stdin)

**Files:**
- Create: `internal/keyholder/bootstrap.go`
- Create: `internal/keyholder/bootstrap_test.go`

**Step 1: Failing test.** `Bootstrap(io.Reader)` reads one line, stores in a private `Key` type with no `String()`/`Format()`, returns it. Reader can be closed after.
**Step 2:** Implement. `Key` is a struct with an unexported field; `Authorization()` returns the rendered header. No accessor returns the raw string.
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(keyholder): stdin bootstrap`.

### Task 4.4: `safe-keyholder` CLI

**Files:** Modify `cmd/safe-keyholder/main.go`.

Reads config, reads key from stdin (one line), starts the proxy on `:8443`, blocks until SIGTERM.

**Step 1:** Manual smoke: `echo sk-test | safe-keyholder`, then `curl -H 'Authorization: dummy' http://127.0.0.1:8443/v1/messages` hits the upstream with the real header.
**Step 2:** Commit: `feat(safe-keyholder): cli entry`.

---

## Milestone 5 — `safe-init` (PID 1)

**Goal:** Inside-the-container orchestrator that brings up fw, dns, keyholder, then execs the agent.

### Task 5.1: Signal forwarding + reaper

**Files:**
- Create: `internal/initd/reaper.go`
- Create: `internal/initd/reaper_test.go`

**Step 1:** Failing test — fork a child, send SIGTERM to parent, assert child receives SIGTERM and parent reaps it.
**Step 2:** Implement using `signal.Notify` + `syscall.Wait4(-1, ...)`.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(initd): signal forwarding and zombie reaping`.

### Task 5.2: User drop

**Files:**
- Create: `internal/initd/userdrop.go`

**Step 1:** Implement `DropTo(uid, gid)` using `syscall.Setuid` and `syscall.Setgid`, plus `prctl(PR_SET_NO_NEW_PRIVS, 1)` and clearing supplementary groups.
**Step 2:** Test in an integration-tagged file that runs as root in CI.
**Step 3:** Commit: `feat(initd): drop privileges`.

### Task 5.3: hidepid remount

**Files:**
- Create: `internal/initd/procmount.go`

**Step 1:** Implement remount of `/proc` with `hidepid=2,gid=<firewall_gid>` via `syscall.Mount`.
**Step 2:** Integration-tagged test inside the container build.
**Step 3:** Commit: `feat(initd): hidepid=2 /proc remount`.

### Task 5.4: Orchestration

**Files:**
- Modify: `cmd/safe-init/main.go`

Sequence:
1. Mount `/proc hidepid=2`.
2. `safe-fw seed` (run as root, wait for exit).
3. Spawn `safe-dns serve` as user `firewall` (with file caps already on the binary).
4. Spawn `safe-keyholder serve` as user `keyholder`; pipe `/run/safe/keyholder.sock` → keyholder's stdin once.
5. Drop to user `agent`, set `no_new_privs`, exec `<agent> [args...]`.
6. Forward signals to the agent PID.
7. On agent exit, exit with the agent's code.

**Step 1:** Manual smoke inside a built container.
**Step 2:** Commit: `feat(initd): bring up fw/dns/keyholder and exec agent`.

---

## Milestone 6 — Container image

**Goal:** A working `safe-runtime` image that bundles all five Go binaries plus the tool layer.

### Task 6.1: Multi-stage Dockerfile — builder

**Files:**
- Create: `Dockerfile`

Builder stage: `golang:1.22` → `COPY . /src` → `make build` → produces `/src/bin/*`.

**Step 1:** `docker build --target builder .` succeeds.
**Step 2:** Commit: `feat(image): builder stage`.

### Task 6.2: Runtime stage — base + system tools

**Files:** Extend `Dockerfile`.

Runtime stage from `debian:bookworm-slim`. Install: `ca-certificates`, `nftables`, `iproute2`, `procps`, `git`, `curl`, `wget`, `jq`, `tini` (we use our own `safe-init` instead but keep tini for fallback debugging). Clean apt cache.

**Step 1:** Image builds. Size check: aim under 200MB at this stage.
**Step 2:** Commit: `feat(image): base + system tools`.

### Task 6.3: Toolchain layers

**Files:** Extend `Dockerfile`.

Add Go (binary from go.dev, not apt), Python (`python3`, `python3-pip`, `python3-venv`), Node (`nodejs`, `npm` from NodeSource), `ripgrep`, `fd-find` (alias `fd`).

**Step 1:** Image builds. Verify versions in a smoke container.
**Step 2:** Commit: `feat(image): language toolchains`.

### Task 6.4: Claude Code

**Files:** Extend `Dockerfile`.

`RUN npm install -g @anthropic-ai/claude-code@<pinned-version>`. Track the pinned version in a file so it's bumpable independently.

**Step 1:** `claude --version` works inside the container.
**Step 2:** Commit: `feat(image): bake Claude Code`.

### Task 6.5: SAFE binaries + users

**Files:** Extend `Dockerfile`.

`COPY --from=builder /src/bin/safe-init /usr/sbin/safe-init` (and friends). Create users `firewall (100)`, `keyholder (101)`, `agent (1000)` with `useradd --system --no-create-home`. Make `/home/agent`, chown agent. `setcap cap_net_admin+ep /usr/sbin/safe-dns`. Create `/etc/safe/` for config.

**Step 1:** Image builds. `getcap /usr/sbin/safe-dns` shows the cap.
**Step 2:** Commit: `feat(image): bake SAFE binaries, users, file caps`.

### Task 6.6: Hardening pass

**Files:** Extend `Dockerfile`.

- `RUN find / -xdev -perm /4000 -type f -exec chmod a-s {} \; || true`
- `RUN rm -f /etc/sudoers /usr/bin/sudo /usr/bin/su || true`
- `USER agent` (build-time only — `safe-init` re-elevates because it must start as PID 1 root).
  - Actually keep build USER as agent; the container is started by Docker with no USER override; we set `ENTRYPOINT ["/usr/sbin/safe-init"]` and safe-init runs as root because of how Docker starts it.

**Step 1:** Image builds. Verify no setuid binaries remain.
**Step 2:** Commit: `feat(image): hardening pass`.

### Task 6.7: Seccomp profile

**Files:**
- Create: `image/seccomp.json`

Start from Docker default profile (`https://github.com/moby/moby/blob/master/profiles/seccomp/default.json`). Add explicit denies for: `ptrace`, `bpf`, `mount`, `umount`, `umount2`, `pivot_root`, `userfaultfd`, `kexec_load`, `init_module`, `delete_module`, `process_vm_readv`, `process_vm_writev`.

**Step 1:** Profile parses with `seccomp-tools` (or our own validator — small Go test).
**Step 2:** Commit: `feat(image): seccomp profile`.

### Task 6.8: ENTRYPOINT

**Files:** Extend `Dockerfile`.

`ENTRYPOINT ["/usr/sbin/safe-init"]`. Document that the first arg to the container = agent name, rest = agent args.

**Step 1:** Manual smoke: `docker run --rm -it --cap-add NET_ADMIN safe-runtime claude --version` should at least reach the agent and print its version.
**Step 2:** Commit: `feat(image): entrypoint = safe-init`.

---

## Milestone 7 — Host CLI — Docker integration

**Goal:** `safe claude` actually launches the container with all hardening flags and the bind mounts.

### Task 7.1: Docker run command builder

**Files:**
- Create: `internal/dockerrun/builder.go`
- Create: `internal/dockerrun/builder_test.go`

**Step 1: Failing test.** Given `Config`, `AgentName`, `CWD`, `RunID`, produce a fully-formed `[]string` argv for `docker run`. Snapshot-test against a golden file.
**Step 2:** Implement. All the flags from design §`docker run` invocation.
**Step 3:** Test passes.
**Step 4:** Commit: `feat(dockerrun): argv builder`.

### Task 7.2: Per-run socket dir

**Files:**
- Create: `internal/dockerrun/socket.go`

**Step 1:** `NewSocketDir() (path, cleanup)` creates `/tmp/safe-<random>/` (mode 0700, owned by user), returns the path and a cleanup function.
**Step 2:** Test in tmp.
**Step 3:** Commit: `feat(dockerrun): per-run socket dir`.

### Task 7.3: Key pipe

**Files:**
- Create: `internal/dockerrun/keypipe.go`

**Step 1:** `PipeKey(socketPath, key string) error` opens a Unix socket, writes one line, closes.
**Step 2:** Integration test pairing with a stub reader.
**Step 3:** Commit: `feat(dockerrun): key pipe`.

### Task 7.4: Customization mount expansion

**Files:**
- Create: `internal/dockerrun/customize.go`
- Create: `internal/dockerrun/customize_test.go`

**Step 1: Failing test.** Given `customization` flags and a fake `~/.claude/` tree, produce the list of `-v src:dst:ro` flags. Hardcoded denylist enforced.
**Step 2:** Implement.
**Step 3:** Tests pass.
**Step 4:** Commit: `feat(dockerrun): expand customization mounts`.

### Task 7.5: `safe <agent> [args...]` end-to-end

**Files:**
- Create: `cmd/safe/run.go`

Hook everything up. Builder + socket + keypipe + customize + `exec.Command("docker", argv...)`. Forward stdio. Wait. Return exit code.

**Step 1:** Manual smoke: build image locally, set `ANTHROPIC_API_KEY=...`, run `bin/safe claude --version`. Should print Claude's version after a brief startup.
**Step 2:** Commit: `feat(cli): safe <agent> end-to-end`.

### Task 7.6: `safe --shell`

**Files:** Modify `cmd/safe/run.go`.

**Step 1:** `bin/safe --shell` lands the user in `bash` inside the sandbox as `agent`. From the shell, `curl https://api.anthropic.com` succeeds (auth error from upstream) and `curl https://evil.com` fails with DNS error.
**Step 2:** Commit: `feat(cli): --shell`.

---

## Milestone 8 — Integration tests

**Goal:** End-to-end tests that run in CI on Linux against a real built image.

### Task 8.1: CI: build image

**Files:**
- Modify: `.gitlab-ci.yml` (add `image` stage that runs `docker build`).

**Step 1:** Pipeline produces an image artifact (or pushes to the GitLab container registry).
**Step 2:** Commit: `ci: build safe-runtime image`.

### Task 8.2: Test harness

**Files:**
- Create: `test/e2e/harness.go`
- Create: `test/e2e/e2e_test.go` (build tag `e2e`).

**Step 1:** A Go test that shells out to `docker run` on the freshly built image with controlled config, captures stdout/stderr, returns it.
**Step 2:** First trivial test: `safe-runtime claude --version` succeeds.
**Step 3:** Commit: `test(e2e): harness`.

### Task 8.3: Allowed FQDN test

**Step 1:** From inside the container, `curl -fsS https://api.anthropic.com/v1/messages` returns a 4xx from Anthropic (proving DNS + nftables + TLS + upstream all work). Empty body / specific status accepted.
**Step 2:** Commit: `test(e2e): allowed FQDN reachable`.

### Task 8.4: Denied FQDN test

**Step 1:** `host evil.com` exits non-zero with NXDOMAIN.
**Step 2:** `curl -m 3 https://evil.com` exits non-zero (DNS failure).
**Step 3:** Commit: `test(e2e): denied FQDN`.

### Task 8.5: Raw IP test

**Step 1:** `curl -m 3 https://1.1.1.1` times out.
**Step 2:** Commit: `test(e2e): raw IP blocked`.

### Task 8.6: Keyholder isolation tests

**Step 1:** From the `agent` user: `cat /proc/$(pgrep safe-keyholder)/environ` → permission denied (or pgrep fails because hidepid=2 hides the pid).
**Step 2:** `ANTHROPIC_API_KEY` is empty or set to the dummy value in the agent's env.
**Step 3:** Commit: `test(e2e): keyholder isolated from agent`.

### Task 8.7: Setuid sweep

**Step 1:** `find / -xdev -perm /4000 -type f 2>/dev/null` returns empty.
**Step 2:** Commit: `test(e2e): no setuid binaries`.

---

## Milestone 9 — Documentation

### Task 9.1: README.md

Replace the stub. Include:
- One-paragraph what it is.
- Install (binary + image).
- Quick start.
- Comparison table with RAGE/CAGE/Argus.
- Pointer to `docs/`.

**Step 1:** Commit: `docs: README`.

### Task 9.2: `docs/CONFIG.md`

Full schema reference for `safe.yaml`. Every field, every default, every validation rule.

**Step 1:** Commit: `docs: config reference`.

### Task 9.3: `docs/CUSTOM.md`

Building a custom image FROM `safe-runtime`. The example from design §Image customization.

**Step 1:** Commit: `docs: custom image guide`.

### Task 9.4: `docs/TEST.md`

Manual agent-prompt scenarios that verify the controls. The list from design §Manual scenarios, expanded with expected agent responses.

**Step 1:** Commit: `docs: manual test scenarios`.

### Task 9.5: `docs/SECURITY.md`

Threat model, defences, known limitations. Cite design doc §Secret containment and §Bypass attempts.

**Step 1:** Commit: `docs: security model`.

---

## Milestone 10 — Release

### Task 10.1: Release script

**Files:**
- Create: `scripts/release.sh`

Tag-driven release. On tag push, GitLab CI: builds linux/arm64 + linux/amd64 + darwin/arm64 + darwin/amd64 binaries, builds + pushes the image, creates a GitLab release page with binaries + image digest.

**Step 1:** Cut `v0.1.0`, verify pipeline produces the release.
**Step 2:** Commit: `ci: tag-driven release`.

### Task 10.2: Smoke install instructions

Update README install section with the real release URLs.

**Step 1:** Commit: `docs: install URLs`.

---

## Cross-cutting standards

- **TDD everywhere.** Write the failing test before the code. No exceptions in unit-test scope.
- **Commits per task.** One green test (or one logical unit) → one commit.
- **Commit format:** `(feat|fix|refactor|test|docs|ci|chore): <one-line summary>`. Never mention Claude or AI in commit messages.
- **Lint clean.** `make lint` must pass on every commit.
- **No `panic` outside `main()`.** Return errors. `main()` may `log.Fatal` on errors that propagate up.
- **Logging.** Use the stdlib `log/slog` package, JSON handler. No `fmt.Println` in non-CLI code.
- **No global state.** Pass dependencies explicitly. Test seams everywhere.
- **Errors wrap.** `fmt.Errorf("doing X: %w", err)`.

## Open questions to resolve during implementation

- The exact org/registry path for the published image (`ghcr.io/<org>/safe-runtime`). Pick during Milestone 0.
- Whether to ship a Homebrew formula. Defer until v0.2.
- Whether to support Podman (in addition to Docker) as the runtime. Likely yes (it speaks the same CLI). Defer until v0.2.
