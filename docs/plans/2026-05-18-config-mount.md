# Mount Merged Config Into Container Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the merged `safe.yaml` actually reach the in-container daemons by bind-mounting it at `/etc/safe/config.yaml`, so `safe-fw` / `safe-dns` / `safe-keyholder` see the user's `upstream_dns`, `allowlist`, and agent config instead of the empty defaults that ship in the image.

**Architecture:**
- The host CLI already loads + merges + validates `safe.yaml` (`internal/config`). After validation, serialize the merged `*config.Config` to YAML, write it to a fresh per-run host directory at mode `0644` inside a `0755` dir, and add `-v <hostdir>:/etc/safe:ro` to the docker argv.
- A per-run *config dir* is separate from the existing per-run *socket dir* (which is `0700` and holds `keyholder.sock`). Mixing the two would either over-restrict the config (firewall/keyholder uids can't read 0700) or over-loosen the socket dir.
- No new public API surface: the host CLI writes the file, `BuildArgv` gains a `ConfigDir` input, and the container side already reads `/etc/safe/config.yaml` (no container changes).

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3` (already imported in `internal/config` and `cmd/safe/printconfig.go`), `github.com/stretchr/testify/require`. Standard library only for filesystem work.

**Pre-flight (do once before Task 1):**
- Working dir: `/Users/rdoorn/git/safe`.
- `make test` must pass on a clean tree before starting; if it doesn't, stop and report.
- Worktree isolation per `superpowers:using-git-worktrees` if executing in parallel; otherwise straight on the current branch is fine (the change is small).

---

### Task 1: Per-run config dir helper

**Files:**
- Create: `internal/dockerrun/configdir.go`
- Create: `internal/dockerrun/configdir_test.go`

**Why this exists:** Centralize the "make a 0755 dir, write `config.yaml` mode 0644, hand back a cleanup" logic so `runAgent` stays thin and the helper is unit-testable without docker.

**Step 1: Write the failing test**

In `internal/dockerrun/configdir_test.go`:

```go
package dockerrun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestNewConfigDirWritesYAML(t *testing.T) {
	dir, cleanup, err := dockerrun.NewConfigDir("safe-cfg-", []byte("upstream_dns:\n  - 1.1.1.1\n"))
	require.NoError(t, err)
	defer cleanup()

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	body, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, "upstream_dns:\n  - 1.1.1.1\n", string(body))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}

func TestNewConfigDirCleanupRemovesEverything(t *testing.T) {
	dir, cleanup, err := dockerrun.NewConfigDir("safe-cfg-", []byte("x: y\n"))
	require.NoError(t, err)
	cleanup()

	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/dockerrun/ -run TestNewConfigDir -v`
Expected: FAIL with `undefined: dockerrun.NewConfigDir`.

**Step 3: Write minimal implementation**

In `internal/dockerrun/configdir.go`:

```go
package dockerrun

import (
	"fmt"
	"os"
	"path/filepath"
)

// NewConfigDir creates a fresh 0755 directory under the system temp root
// with the given prefix, writes the YAML payload to config.yaml at mode
// 0644 inside it, and returns the directory path plus a cleanup func.
//
// The file holds no secrets (resolvers, allowlist, agent metadata only),
// so it is intentionally world-readable inside the container — firewall,
// keyholder, and agent uids all need to read their slice of it.
func NewConfigDir(prefix string, configYAML []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", func() {}, fmt.Errorf("mktemp: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, configYAML, 0o644); err != nil { //nolint:gosec // public config, no secrets
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("write %s: %w", path, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/dockerrun/ -run TestNewConfigDir -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/dockerrun/configdir.go internal/dockerrun/configdir_test.go
git commit -m "feat(dockerrun): per-run config dir helper"
```

---

### Task 2: BuildArgv mounts the config dir at /etc/safe:ro

**Files:**
- Modify: `internal/dockerrun/builder.go:11-27` (Inputs struct) and `:90-95` (mount block)
- Modify: `internal/dockerrun/builder_test.go` (add new test + extend existing where needed)

**Step 1: Write the failing test**

Append to `internal/dockerrun/builder_test.go`:

```go
func TestBuildArgvBindsConfigDir(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(argv, " "), "-v /tmp/safe-cfg-x:/etc/safe:ro")
}

func TestBuildArgvRequiresConfigDir(t *testing.T) {
	_, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		// ConfigDir intentionally omitted
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "config dir")
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/dockerrun/ -run TestBuildArgv -v`
Expected: both new tests FAIL (no `ConfigDir` field; no mount line; no error).

**Step 3: Implement**

In `internal/dockerrun/builder.go`, add to `Inputs`:

```go
	// ConfigDir is the host directory holding the merged config.yaml.
	// Bind-mounted read-only at /etc/safe inside the container.
	ConfigDir string
```

In `BuildArgv`, after the existing nil/agent/image checks add:

```go
	if in.ConfigDir == "" {
		return nil, fmt.Errorf("config dir is required")
	}
```

In the mount block (currently `-v in.CWD:/workspace ...`), add the config mount:

```go
	argv = append(argv,
		"-v", in.CWD+":/workspace",
		"-v", in.HomeVolumeName_unused, // <-- existing line, do not change; example placeholder
	)
```

(Concretely: insert one extra `argv = append(argv, "-v", in.ConfigDir+":/etc/safe:ro")` line right after the `-v in.SocketDir+":/run/safe"` append. Keep ordering deterministic for tests.)

**Step 4: Update other BuildArgv callers / tests**

Every existing builder test (`TestBuildArgvHasHardeningFlags`, `TestBuildArgvBindsWorkspace`, `TestBuildArgvBindsSocketDir`, the agent-not-in-config / no-image tests, etc.) now needs `ConfigDir: "/tmp/safe-cfg-x"` (or similar). Add it to each Inputs literal. Don't loosen the negative tests — they still expect their existing errors to fire because those checks run before the new one.

Check call order: `nil config → agent lookup → image check → config dir check`. The current negative tests must keep working without `ConfigDir`, so keep the new check *after* the existing ones. If a negative test now changes outcome, adjust by giving it `ConfigDir`.

**Step 5: Run all dockerrun tests**

Run: `go test ./internal/dockerrun/ -v`
Expected: PASS.

**Step 6: Commit**

```bash
git add internal/dockerrun/builder.go internal/dockerrun/builder_test.go
git commit -m "feat(dockerrun): bind-mount merged config at /etc/safe:ro"
```

---

### Task 3: runAgent serializes config and passes ConfigDir

**Files:**
- Modify: `cmd/safe/run.go` (`runAgent`, `buildDockerArgv`)
- Modify: `cmd/safe/run_test.go` if it exists; otherwise add a small test that exercises the YAML serialization path

**Step 1: Write the failing test**

Check first: `ls cmd/safe/run_test.go`. If absent, create `cmd/safe/run_test.go` with:

```go
package main

import (
	"testing"

	"github.com/rdoorn/safe/internal/config"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMarshalMergedConfigRoundtrips(t *testing.T) {
	in := &config.Config{
		UpstreamDNS: []string{"1.1.1.1", "9.9.9.9"},
		Allowlist:   []string{"api.anthropic.com"},
		Agents: map[string]config.Agent{
			"claude": {
				Image:      "ghcr.io/example/safe-runtime:0.1.0",
				Entrypoint: "claude",
				AuthEnv:    "ANTHROPIC_API_KEY",
				BaseURL:    "https://api.anthropic.com",
				LockedTools: []string{"Read"},
			},
		},
	}
	data, err := yaml.Marshal(in)
	require.NoError(t, err)

	out, err := config.Parse(data)
	require.NoError(t, err)
	require.Equal(t, in.UpstreamDNS, out.UpstreamDNS)
	require.Equal(t, in.Allowlist, out.Allowlist)
	require.Equal(t, in.Agents["claude"].Image, out.Agents["claude"].Image)
}
```

This is a guard test against future changes that break the round-trip (e.g. unexported fields, custom MarshalYAML drift).

**Step 2: Run it; expected PASS already**

Run: `go test ./cmd/safe/ -run TestMarshalMergedConfig -v`
Expected: PASS (printconfig.go already uses `yaml.Marshal(merged)`).

The point of this test is regression coverage, not red-then-green. If it surprisingly fails, stop and report.

**Step 3: Modify `runAgent`**

In `cmd/safe/run.go`:

1. Add `"gopkg.in/yaml.v3"` to imports (if not already).
2. After `socketDir, cleanupSocket, err := dockerrun.NewSocketDir("safe-")` and its `defer cleanupSocket()`, add:

```go
	configYAML, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	configDir, cleanupConfig, err := dockerrun.NewConfigDir("safe-cfg-", configYAML)
	if err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	defer cleanupConfig()
```

3. Change the `buildDockerArgv` signature to accept `configDir string`, and forward it via `dockerrun.Inputs.ConfigDir`.

**Step 4: Run host CLI tests**

Run: `go test ./cmd/safe/ -v`
Expected: PASS.

**Step 5: Run full test + lint**

Run: `make test && make lint`
Expected: both PASS. If lint complains about `0o644` in `configdir.go`, the existing `//nolint:gosec` comment we added should silence it; if it doesn't, fix the directive.

**Step 6: Commit**

```bash
git add cmd/safe/run.go cmd/safe/run_test.go
git commit -m "feat(safe): mount merged config into container"
```

---

### Task 4: Manual verification (no commit)

**Goal:** Confirm the original `safe claude` failure is gone end-to-end.

**Step 1: Rebuild host binary**

Run: `make build`
Expected: `bin/safe` updated, no errors.

**Step 2: Rebuild image**

Run: `docker buildx build -t safe-runtime:dev .`
Expected: image built. (The image doesn't need to change — Dockerfile is untouched — but rebuild so the user can swap their `image:` in `safe.yaml` to `safe-runtime:dev` for the test.)

**Step 3: Point safe.yaml at the dev image**

Edit (or create with `bin/safe init`) the per-project `safe.yaml`. Set:

```yaml
agents:
  claude:
    image: safe-runtime:dev
```

Keep `upstream_dns: [1.1.1.1, 1.0.0.1]` in there (it should already be in the init template).

**Step 4: Run safe claude with --doctor first**

Run: `bin/safe --doctor` (or `safe --doctor` if `make install` has been run).
Expected: clean output, no errors.

**Step 5: Run safe claude**

Run: `bin/safe claude --help` (use `--help` so the agent exits immediately and we don't sit in an interactive session).
Expected (the only acceptable success state):
- `safe-init: hidepid remount skipped: ...` line still present (it's a known best-effort warning unless `--cap-add SYS_ADMIN` is set; not in scope here).
- **No** `upstream_dns: at least one resolver required` line.
- **No** `safe-fw seed: exit status 1` line.
- The agent reaches its own `--help` output.

If `upstream_dns: at least one resolver required` still fires, stop. Investigate: `docker run --rm -v /tmp/safe-cfg-<runid>:/etc/safe:ro safe-runtime:dev cat /etc/safe/config.yaml` to confirm the file is in there (you'll need to grab the runid from a `safe` run with `--name safe-<runid>` visible in `docker ps`).

**Step 6: Report back, no commit**

Verification only. The three feature commits from tasks 1–3 are the deliverable.

---

## Closing notes

- Per `[[feedback-commit-cadence]]` in auto-memory: commit per TDD task (3 commits total here), not one mega-commit.
- Per `[[feedback-dependency-age]]`: no new deps in this plan; if you find yourself reaching for one, stop and ask.
- The `hidepid` warning is **not** in scope. Don't touch `internal/initd/procmount*.go` in this branch.
