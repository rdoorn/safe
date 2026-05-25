# RTK Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bundle RTK into the `safe-runtime` image and wire it up at container startup when `rtk: enabled: true` in `safe.yaml` (default true), so agents automatically benefit from 60–90% token reduction on Bash commands.

**Architecture:** `safe-init` loads the config once at startup, runs `rtk init -g` as uid 1000 before exec-ing the agent (when enabled), and injects `RTK_TELEMETRY_DISABLED=1` into the agent env. RTK owns its own `settings.json` merge logic; SAFE does not maintain the hook format.

**Tech Stack:** Go (`os/exec`, `syscall.SysProcAttr`), YAML (`gopkg.in/yaml.v3`), Dockerfile multi-arch (`$TARGETARCH`), `testify/require`.

**Design doc:** `docs/plans/2026-05-25-rtk-integration-design.md`

---

### Task 1: Config schema — add `RTK` struct

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/merge.go`
- Test: `internal/config/config_test.go`
- Test: `internal/config/merge_test.go`

**Step 1: Write failing tests**

Add to `internal/config/config_test.go`:

```go
func TestParseRTKEnabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
rtk:
  enabled: true
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.True(t, cfg.RTK.IsEnabled())
}

func TestParseRTKDisabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
rtk:
  enabled: false
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.False(t, cfg.RTK.IsEnabled())
}

func TestParseRTKAbsentDefaultsToEnabled(t *testing.T) {
	src := `
agents:
  claude:
    image: x
    entrypoint: claude
    auth_env: ANTHROPIC_API_KEY
    base_url: https://api.anthropic.com
    locked_tools: [Read]
allowlist: [api.anthropic.com]
upstream_dns: [1.1.1.1]
`
	cfg, err := config.Parse([]byte(src))
	require.NoError(t, err)
	require.True(t, cfg.RTK.IsEnabled(), "absent rtk block must default to enabled")
}
```

Add to `internal/config/merge_test.go`:

```go
func TestMergeRTKOverlayDisables(t *testing.T) {
	yes := true
	no := false
	base := &config.Config{RTK: config.RTK{Enabled: &yes}}
	overlay := &config.Config{RTK: config.RTK{Enabled: &no}}
	out := config.Merge(base, overlay)
	require.False(t, out.RTK.IsEnabled())
}

func TestMergeRTKOverlayAbsentPreservesBase(t *testing.T) {
	yes := true
	base := &config.Config{RTK: config.RTK{Enabled: &yes}}
	overlay := &config.Config{}
	out := config.Merge(base, overlay)
	require.True(t, out.RTK.IsEnabled())
}
```

**Step 2: Run tests to confirm they fail**

```
make test 2>&1 | grep -A3 "TestParseRTK\|TestMergeRTK"
```
Expected: compile error — `RTK` undefined.

**Step 3: Implement**

Add to `internal/config/config.go` (after the `Audit` struct, before `Parse`):

```go
// RTK controls whether RTK (Rust Token Killer) is enabled for the agent.
// RTK reduces LLM token consumption by filtering command output.
// Defaults to enabled when absent.
type RTK struct {
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled returns true when RTK is active. Nil (absent from config) means
// enabled — RTK is opt-out, not opt-in.
func (r RTK) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}
```

Add `RTK RTK \`yaml:"rtk"\`` to the `Config` struct, after `Audit`:

```go
type Config struct {
	ProjectID      string           `yaml:"project_id"`
	Agents         map[string]Agent `yaml:"agents"`
	Allowlist      []string         `yaml:"allowlist"`
	UpstreamDNS    []string         `yaml:"upstream_dns"`
	Mounts         []string         `yaml:"mounts"`
	EnvPassthrough []string         `yaml:"env_passthrough"`
	ExtraCaps      []string         `yaml:"extra_caps"`
	Resources      Resources        `yaml:"resources"`
	Audit          Audit            `yaml:"audit"`
	RTK            RTK              `yaml:"rtk"`
}
```

Add `mergeRTK` to `internal/config/merge.go` (after `mergeAudit`):

```go
func mergeRTK(base, overlay RTK) RTK {
	if overlay.Enabled != nil {
		return RTK{Enabled: overlay.Enabled}
	}
	return base
}
```

Wire it into `Merge`:

```go
out := &Config{
	// ... existing fields ...
	RTK: mergeRTK(base.RTK, overlay.RTK),
}
```

**Step 4: Run tests**

```
make test 2>&1 | grep -A3 "TestParseRTK\|TestMergeRTK"
```
Expected: all three config tests and both merge tests PASS.

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/merge.go \
        internal/config/config_test.go internal/config/merge_test.go
git commit -m "feat(config): add RTK struct with default-enabled semantics"
```

---

### Task 2: Refactor `safe-init` to load config once

Currently `resolveAuthMode` loads `config.yaml` internally. This task extracts that load to `run()` so RTK can reuse the same `*Config` without a second disk read.

**Files:**
- Modify: `cmd/safe-init/main.go`

**Step 1: Write a failing test**

Add `cmd/safe-init/main_test.go` (new file):

```go
package main

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
)

func TestResolveAuthModeAPIKey(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {AuthEnv: "ANTHROPIC_API_KEY"},
		},
	}
	mode, err := resolveAuthMode(cfg, "claude")
	require.NoError(t, err)
	require.Equal(t, "apikey", mode)
}

func TestResolveAuthModeOAuth(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"claude": {AuthCredentialsFile: "/home/user/.claude/.credentials.json"},
		},
	}
	mode, err := resolveAuthMode(cfg, "claude")
	require.NoError(t, err)
	require.Equal(t, "oauth", mode)
}

func TestResolveAuthModeUnknownAgent(t *testing.T) {
	cfg := &config.Config{Agents: map[string]config.Agent{}}
	_, err := resolveAuthMode(cfg, "unknown")
	require.Error(t, err)
}
```

**Step 2: Run to confirm failure**

```
make test 2>&1 | grep -A3 "TestResolveAuthMode"
```
Expected: compile error — `resolveAuthMode` has wrong signature.

**Step 3: Implement**

In `cmd/safe-init/main.go`, change `resolveAuthMode` from loading its own config to accepting one:

```go
// resolveAuthMode inspects the agent config to decide whether it uses
// a static API key or OAuth credentials.
func resolveAuthMode(cfg *config.Config, agentName string) (string, error) {
	a, ok := cfg.Agents[agentName]
	if !ok {
		return "", fmt.Errorf("agent %q not in config", agentName)
	}
	switch {
	case a.AuthCredentialsFile != "":
		return "oauth", nil
	case a.AuthEnv != "":
		return "apikey", nil
	default:
		return "", fmt.Errorf("agent %q has neither auth_env nor auth_credentials_file", agentName)
	}
}
```

In `run()`, load the config at the top (before the `keyholderEnabled` block) and pass it in:

```go
func run(agentName string, agentArgs []string) error {
	logStage := func(stage int, msg string) {
		fmt.Fprintf(os.Stderr, "safe-init: stage=%d %s\n", stage, msg)
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var secret []byte
	authMode := ""
	if keyholderEnabled {
		logStage(0, "read bootstrap secret (FIRST; before any other work)")
		var ferr error
		authMode, ferr = resolveAuthMode(cfg, agentName)
		if ferr != nil {
			return fmt.Errorf("determine auth mode: %w", ferr)
		}
		// ... rest of keyholderEnabled block unchanged ...
	}
	// ... rest of run() unchanged for now ...
```

**Step 4: Run tests**

```
make test 2>&1 | grep -A3 "TestResolveAuthMode"
```
Expected: PASS.

**Step 5: Full test suite**

```
make test
```
Expected: all tests pass.

**Step 6: Commit**

```bash
git add cmd/safe-init/main.go cmd/safe-init/main_test.go
git commit -m "refactor(safe-init): load config once in run(), pass to resolveAuthMode"
```

---

### Task 3: Implement `initRTK` in `safe-init`

**Files:**
- Create: `cmd/safe-init/rtk.go`
- Create: `cmd/safe-init/rtk_test.go`

**Step 1: Write failing tests**

Create `cmd/safe-init/rtk_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitRTKCallsBinary(t *testing.T) {
	dir := t.TempDir()
	flagFile := filepath.Join(dir, "ran")

	// Fake rtk binary: writes a flag file then exits 0.
	fakeBin := filepath.Join(dir, "rtk")
	script := "#!/bin/sh\ntouch " + flagFile + "\n"
	require.NoError(t, os.WriteFile(fakeBin, []byte(script), 0o755))

	initRTK(fakeBin)

	_, err := os.Stat(flagFile)
	require.NoError(t, err, "fake rtk binary was not called")
}

func TestInitRTKNonZeroExitDoesNotPanic(t *testing.T) {
	dir := t.TempDir()

	// Fake rtk binary that fails.
	fakeBin := filepath.Join(dir, "rtk")
	require.NoError(t, os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	// Should not panic or call t.Fatal.
	initRTK(fakeBin)
}

func TestInitRTKMissingBinaryDoesNotPanic(t *testing.T) {
	initRTK("/nonexistent/rtk")
}
```

> **Note:** These tests run `initRTK` with the *current* uid (no setuid in test environment). The fake binaries execute as whoever runs `make test`. The `SysProcAttr.Credential` in the real implementation only applies in the running container (as root). Do **not** add `Credential` to the test path — it will fail outside the container. Use the `binPath` parameter to inject the fake binary; keep credentials in the container-only code path.

**Step 2: Run to confirm failure**

```
make test 2>&1 | grep -A3 "TestInitRTK"
```
Expected: compile error — `initRTK` undefined.

**Step 3: Implement**

Create `cmd/safe-init/rtk.go`:

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const rtkBin = "/usr/local/bin/rtk"

// initRTK runs `rtk init -g` as the agent uid so RTK can write its
// Claude Code PreToolUse hook into /home/agent/.claude/settings.json.
// RTK manages its own merge logic; if settings.json already exists (from
// a customization.settings mount) RTK merges into it.
//
// A non-zero exit is logged as a warning and does not abort startup —
// the agent starts regardless, just without RTK's hook.
func initRTK(binPath string) {
	fmt.Fprintln(os.Stderr, "safe-init: rtk: enabled, telemetry disabled")
	cmd := exec.Command(binPath, "init", "-g") //nolint:gosec // binPath is a constant at call sites
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"HOME=/home/agent",
		"RTK_TELEMETRY_DISABLED=1",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:         defaultAgentUID,
			Gid:         defaultAgentGID,
			NoSetGroups: true,
		},
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: rtk: hook init failed:", err, "(continuing)")
		return
	}
	fmt.Fprintln(os.Stderr, "safe-init: rtk: hook initialized")
}
```

**Step 4: Run tests**

```
make test 2>&1 | grep -A3 "TestInitRTK"
```
Expected: all three tests PASS.

**Step 5: Commit**

```bash
git add cmd/safe-init/rtk.go cmd/safe-init/rtk_test.go
git commit -m "feat(safe-init): add initRTK — runs rtk init -g as agent uid"
```

---

### Task 4: Wire RTK into `run()` and agent env

**Files:**
- Modify: `cmd/safe-init/main.go`

**Step 1: Write failing tests**

Add to `cmd/safe-init/main_test.go`:

```go
func TestAgentEnvRTKTelemetryPresent(t *testing.T) {
	env := agentEnv([]string{}, true)
	require.Contains(t, env, "RTK_TELEMETRY_DISABLED=1")
}

func TestAgentEnvRTKTelemetryAbsentWhenDisabled(t *testing.T) {
	env := agentEnv([]string{}, false)
	for _, e := range env {
		require.NotEqual(t, "RTK_TELEMETRY_DISABLED=1", e)
	}
}
```

**Step 2: Run to confirm failure**

```
make test 2>&1 | grep -A3 "TestAgentEnvRTK"
```
Expected: compile error — `agentEnv` has wrong signature.

**Step 3: Implement**

In `cmd/safe-init/main.go`, update `agentEnv` to accept a `rtkEnabled bool` parameter:

```go
func agentEnv(parent []string, rtkEnabled bool) []string {
	filtered := parent[:0:0]
	for _, e := range parent {
		switch {
		case strings.HasPrefix(e, "HOME="),
			strings.HasPrefix(e, "USER="),
			strings.HasPrefix(e, "LOGNAME="):
			continue
		default:
			filtered = append(filtered, e)
		}
	}
	out := append(filtered,
		"HOME=/home/agent",
		"USER=agent",
		"LOGNAME=agent",
		"GOTMPDIR="+goTmpDir,
		"GOPATH=/home/agent/.cache/go",
		"GOMODCACHE=/home/agent/.cache/go/pkg/mod",
		"NPM_CONFIG_IGNORE_SCRIPTS=true",
		"PYENV_ROOT=/opt/pyenv",
		"FNM_DIR=/opt/fnm",
		"PATH=/opt/pyenv/shims:/opt/pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	)
	if rtkEnabled {
		out = append(out, "RTK_TELEMETRY_DISABLED=1")
	}
	return out
}
```

Update `startAgent` to accept and forward `rtkEnabled`:

```go
func startAgent(bin string, args []string, uid, gid uint32, rtkEnabled bool) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...) //nolint:gosec
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = agentEnv(os.Environ(), rtkEnabled)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	return cmd, nil
}
```

In `run()`, add the RTK init call between keyholder spawn and `hardenAgentSubtree`, then pass `rtkEnabled` to `startAgent`:

```go
	// RTK token optimiser: run `rtk init -g` as agent uid so it can write
	// the Claude Code hook into /home/agent/.claude/settings.json.
	// Runs after stageClaudeSettings so RTK merges into any staged file.
	rtkEnabled := cfg.RTK.IsEnabled()
	if rtkEnabled {
		initRTK(rtkBin)
	} else {
		fmt.Fprintln(os.Stderr, "safe-init: rtk: disabled")
	}

	if err := hardenAgentSubtree(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: agent-subtree hardening skipped:", err)
	}

	agentBin := resolveAgentPath(agentName)
	logStage(6, fmt.Sprintf("spawn agent: bin=%s args=%v uid=%d", agentBin, agentArgs, defaultAgentUID))
	agentCmd, err := startAgent(agentBin, agentArgs, defaultAgentUID, defaultAgentGID, rtkEnabled)
```

**Step 4: Run tests**

```
make test
```
Expected: all tests pass.

**Step 5: Commit**

```bash
git add cmd/safe-init/main.go cmd/safe-init/main_test.go
git commit -m "feat(safe-init): wire RTK into startup sequence and agent env"
```

---

### Task 5: Dockerfile — install RTK binary

**Files:**
- Modify: `Dockerfile`

**Step 1: Verify asset names before editing**

Check the exact tarball structure. Run once:

```bash
curl -fsSL https://github.com/rtk-ai/rtk/releases/download/v0.40.0/rtk-x86_64-unknown-linux-musl.tar.gz \
  | tar -tz | head -20
```

Confirm the binary inside is named `rtk` (likely at root or `./rtk`). Note the exact path for the `tar -xzf` step below; adjust `--strip-components` if it's inside a subdirectory.

**Step 2: Add ARG and install block to Dockerfile**

After the `pnpm` install block and before the `pyenv` block, add:

```dockerfile
# --- RTK: Rust Token Killer (token-efficient command output for LLM agents) ---
# Pin per the "at least 7 days old" rule. v0.40.0 released 2026-05-13 (12d old).
# Assets: rtk-x86_64-unknown-linux-musl.tar.gz (amd64, static musl)
#         rtk-aarch64-unknown-linux-gnu.tar.gz  (arm64, dynamic gnu)
ARG RTK_VERSION=v0.40.0
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) RTK_TARBALL=rtk-x86_64-unknown-linux-musl.tar.gz ;; \
      arm64) RTK_TARBALL=rtk-aarch64-unknown-linux-gnu.tar.gz ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/${RTK_VERSION}/${RTK_TARBALL}" \
      -o /tmp/rtk.tar.gz; \
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/${RTK_VERSION}/checksums.txt" \
      -o /tmp/rtk-checksums.txt; \
    grep "${RTK_TARBALL}" /tmp/rtk-checksums.txt | sha256sum -c -; \
    mkdir -p /tmp/rtk-extract; \
    tar -xzf /tmp/rtk.tar.gz -C /tmp/rtk-extract; \
    install -m0755 /tmp/rtk-extract/rtk /usr/local/bin/rtk; \
    rm -rf /tmp/rtk.tar.gz /tmp/rtk-checksums.txt /tmp/rtk-extract
```

> **If the binary is at a different path inside the tarball** (e.g. `./rtk-v0.40.0/rtk`), adjust the `install` source path accordingly. The `tar -tz` from step 1 tells you the exact layout.

**Step 3: Build and verify**

```bash
docker buildx build --platform linux/amd64 -t safe-runtime:rtk-test .
docker run --rm safe-runtime:rtk-test rtk --version
```
Expected: prints `rtk 0.40.0` (or similar).

**Step 4: Arm64 spot-check (if buildx is available)**

```bash
docker buildx build --platform linux/arm64 -t safe-runtime:rtk-test-arm .
```
Expected: build succeeds.

**Step 5: Commit**

```bash
git add Dockerfile
git commit -m "feat(image): add RTK v0.40.0 binary to safe-runtime"
```

---

### Task 6: `safe.yaml` template and `docs/CONFIG.md`

**Files:**
- Modify: `cmd/safe/init.go`
- Modify: `docs/CONFIG.md`

**Step 1: Add `rtk:` block to template**

In `cmd/safe/init.go`, find the `initTemplate` const. Add before the closing backtick, after the `audit:` block:

```yaml

# RTK token optimiser: reduces LLM token consumption 60-90% by filtering
# Bash command output. Enabled by default. Disable if you need raw output.
rtk:
  enabled: true
```

**Step 2: Verify template renders**

```bash
mkdir -p /tmp/rtk-init-test && cd /tmp/rtk-init-test
safe init 2>&1 || true
grep -A2 "rtk:" .safe/safe.yaml
cd - && rm -rf /tmp/rtk-init-test
```
Expected: `rtk:\n  enabled: true` appears in the output file.

**Step 3: Add to `docs/CONFIG.md`**

Find the schema section and add after the `audit:` entry:

```markdown
### `rtk`

Controls the in-container [RTK](https://github.com/rtk-ai/rtk) token optimiser.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Run `rtk init -g` at startup and set `RTK_TELEMETRY_DISABLED=1` in the agent env. RTK intercepts Bash command output and compresses it 60–90% before it reaches the LLM. |

Telemetry is unconditionally disabled (the container is firewalled; it would fail anyway).

To tune RTK's behaviour (excluded commands, tee mode, etc.), mount your `~/.config/rtk/config.toml` via `customization.mounts`:

```yaml
mounts:
  - ~/.config/rtk/config.toml:/home/agent/.config/rtk/config.toml:ro
```
```

**Step 4: Run the full test suite**

```bash
make test
```
Expected: all tests pass.

**Step 5: Commit**

```bash
git add cmd/safe/init.go docs/CONFIG.md
git commit -m "docs: add rtk: block to safe.yaml template and CONFIG.md"
```

---

### Task 7: End-to-end smoke test

This is a manual verification step; no automated test is added here (the full integration-test harness is tracked in M8 of the implementation plan).

**Step 1: Build a fresh image**

```bash
docker buildx build -t safe-runtime:dev .
```

**Step 2: Start a shell session with RTK enabled (default)**

```bash
safe --shell
```

**Step 3: Inside the container, verify**

```bash
# RTK binary is present and executable
rtk --version

# Hook was written to settings.json
cat /home/agent/.claude/settings.json | grep -A5 "PreToolUse"

# Telemetry env var is set
echo $RTK_TELEMETRY_DISABLED   # must print: 1

# RTK processes a command correctly
rtk git status
```

**Step 4: Disable RTK and verify it's skipped**

In `.safe/safe.yaml`, temporarily set `rtk: enabled: false`. Re-run `safe --shell`. Container stderr must include `safe-init: rtk: disabled`. The settings.json must not contain the RTK hook entry.

Restore `enabled: true` when done.
