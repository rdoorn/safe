# Move SAFE runtime state into <cwd>/.safe/ Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the macOS Docker Desktop bind-mount bug surfaced during verification of `2026-05-18-config-mount.md`. Move all per-project SAFE state — `safe.yaml`, per-run config dir, per-run socket dir — into `<cwd>/.safe/` so paths are reliably inside Docker Desktop's default file-sharing whitelist. Ensure `safe init` keeps `.safe/` out of source control / docker image context.

**Background:**

`os.MkdirTemp("", prefix)` writes to `$TMPDIR`, which on macOS is `/var/folders/<uid>/.../T/`. Docker Desktop's default sharing list does not reliably include this path; the bind mount silently produces an empty directory inside the container. Confirmed by probe:

```
$ ls /etc/safe inside container, when host dir is /var/folders/.../T/safe-cfg-*: empty
$ ls /etc/safe inside container, when host dir is /Users/.../safe-probe:           contains config.yaml
```

The fix is to put per-run host dirs under the project's working directory (which is already bind-mounted at `/workspace` and therefore guaranteed shared by Docker Desktop).

**Architecture:**

```
<cwd>/
├── .safe/
│   ├── safe.yaml              # user-editable config (moved from <cwd>/safe.yaml)
│   └── <runid>/               # per-run state, created on each `safe <agent>` invocation
│       ├── config/
│       │   └── config.yaml    # mode 0644, bind-mounted at /etc/safe:ro
│       └── socket/            # mode 0700, bind-mounted at /run/safe
│           └── keyholder.sock # created by safe-keyholder inside the container
```

`safe init` ensures `.safe/` exists, writes the template at `.safe/safe.yaml`, and adds `.safe/` to `.gitignore` (creating the file if absent) and to `.dockerignore` (only if that file already exists; do not create one just for this).

**Tech Stack:** Go 1.25, existing test patterns (testify/require), no new deps.

**Pre-flight:**
- Working dir: `/Users/rdoorn/git/safe`. Branch: `main`. Skip worktree (per prior user preference for this fix branch).
- Tasks 1–3 of `2026-05-18-config-mount.md` are already merged (`8b79c58`, `71e6afb`, `45c42e8`, `18093bc`). This plan builds on top.
- `make test` and `make lint` must be green at start of each task.
- Per `[[feedback-commit-cadence]]`: commit per TDD task.

**Out of scope:**
- Migration of an existing `<cwd>/safe.yaml`. Hard cutover: the user moves their own file. The plan flags this in Task B.
- The pre-existing `os.Exit`-skips-defers cleanup leak from the previous code review. Track separately.
- `.dockerignore` creation when absent (only update if it exists).

---

### Task A: Helpers consume a pre-made dir instead of creating their own temp dir

**Files:**
- Modify: `internal/dockerrun/configdir.go` — rename/refactor `NewConfigDir` to `WriteConfigDir(dir string, configYAML []byte) error`. It assumes `dir` exists, sets it to 0755, writes `dir/config.yaml` at 0644 (with umask-defensive chmod).
- Modify: `internal/dockerrun/socket.go` — refactor `NewSocketDir(prefix string) (string, func(), error)` to `PrepareSocketDir(dir string) error`. It assumes `dir` exists and sets it to 0700.
- Modify: `internal/dockerrun/configdir_test.go` — rename tests to match; pre-create `dir` via `t.TempDir()`.
- Modify: `internal/dockerrun/socket_test.go` — same shape.

**Rationale:** The new orchestrator (`runAgent`) will compute one `runRoot = <cwd>/.safe/<runid>` and prepare both subdirs under it. Helpers shouldn't own the temp-dir choice anymore.

**Step 1: Write the failing tests**

Rewrite the contents of `internal/dockerrun/configdir_test.go`:

```go
package dockerrun_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestWriteConfigDir(t *testing.T) {
	dir := t.TempDir()
	err := dockerrun.WriteConfigDir(dir, []byte("upstream_dns:\n  - 1.1.1.1\n"))
	require.NoError(t, err)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	body, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, "upstream_dns:\n  - 1.1.1.1\n", string(body))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}

func TestWriteConfigDirOverridesRestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	dir := t.TempDir()
	require.NoError(t, dockerrun.WriteConfigDir(dir, []byte("x: y\n")))

	fi, err := os.Stat(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}
```

And `internal/dockerrun/socket_test.go` (replace `TestNewSocketDirCreatesAndCleans` and `TestNewSocketDirUniquePerCall`):

```go
func TestPrepareSocketDirSets0700(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, dockerrun.PrepareSocketDir(dir))

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}
```

**Step 2: Run; expect FAIL** (undefined `WriteConfigDir` / `PrepareSocketDir`).

`go test ./internal/dockerrun/ -run 'TestWriteConfigDir|TestPrepareSocketDir' -v`

**Step 3: Implement**

Rewrite `internal/dockerrun/configdir.go`:

```go
package dockerrun

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteConfigDir assumes dir exists and is empty; widens it to 0755 and
// writes config.yaml inside at mode 0644. The mode is set defensively
// (Chmod after WriteFile) so a strict caller umask doesn't downgrade it,
// because firewall/keyholder/agent uids inside the container all need to
// read the file (it holds no secrets).
func WriteConfigDir(dir string, configYAML []byte) error {
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, configYAML, 0o644); err != nil { //nolint:gosec
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
```

Rewrite `internal/dockerrun/socket.go`:

```go
package dockerrun

import (
	"fmt"
	"os"
)

// PrepareSocketDir assumes dir exists; sets it to 0700 so only the host
// user (and root inside the container) can traverse to the socket file
// that safe-keyholder will create later.
func PrepareSocketDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}
```

**Step 4: Update callers in `cmd/safe/run.go` later (Task D)**. For now the call sites won't compile — that's fine for the helper-package test step. Just confirm the helper-package tests pass:

`go test ./internal/dockerrun/ -v`

(The cmd/safe package will fail to build until Task D. Run only the dockerrun tests for now.)

**Step 5: Commit**

```bash
git add internal/dockerrun/configdir.go internal/dockerrun/configdir_test.go internal/dockerrun/socket.go internal/dockerrun/socket_test.go
git commit -m "refactor(dockerrun): write to caller-provided dirs"
```

---

### Task B: Project config path moves to `<cwd>/.safe/safe.yaml`

**Files:**
- Modify: `internal/config/loader.go` — change project path from `filepath.Join(cwd, "safe.yaml")` to `filepath.Join(cwd, ".safe", "safe.yaml")`.
- Modify: `internal/config/loader_test.go` — update fixtures to write the file at the new path.

**Note:** No backwards compat. If the user has an old `<cwd>/safe.yaml`, this branch will stop seeing it. The CLAUDE.md / README / verification steps must call out the move (handled in Task E and the README, but not in code). The user has agreed to migrate manually.

**Step 1: Update loader_test.go**

Find every test that writes `safe.yaml` directly under `cwd`. Update them to first `os.Mkdir(filepath.Join(cwd, ".safe"), 0o755)`, then write to `<cwd>/.safe/safe.yaml`. Same for `printconfig_test.go` if it does the same.

**Step 2: Run tests; expect FAIL**

`go test ./internal/config/ ./cmd/safe/ -v`
Expected: tests that depend on the old project path will fail or stop finding the file.

**Step 3: Update `loader.go:36`**

```go
paths := []string{
	filepath.Join(xdgConfigDir, "safe", configFilename),
	filepath.Join(cwd, ".safe", configFilename),
}
```

**Step 4: Verify tests pass**

`go test ./internal/config/ ./cmd/safe/ -v`

**Step 5: Commit**

```bash
git add internal/config/loader.go internal/config/loader_test.go cmd/safe/printconfig_test.go
git commit -m "feat(config): project config now lives at <cwd>/.safe/safe.yaml"
```

---

### Task C: `safe init` writes `.safe/safe.yaml` and updates ignore files

**Files:**
- Modify: `cmd/safe/init.go`:
  - Target path becomes `<cwd>/.safe/safe.yaml` (was `<cwd>/safe.yaml`).
  - Before writing, ensure `<cwd>/.safe/` exists (`os.MkdirAll`, mode 0o755).
  - After writing, call new helpers `ensureIgnore(cwd, ".gitignore", ".safe/", createIfMissing=true)` and `ensureIgnore(cwd, ".dockerignore", ".safe/", createIfMissing=false)`.
- Create: tests for the ignore-file helper in `cmd/safe/init_test.go` (or extend if it exists).

**Step 1: Write failing tests**

In `cmd/safe/init_test.go` (create if missing):

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunInitWritesUnderDotSafe(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	body, err := os.ReadFile(filepath.Join(cwd, ".safe", "safe.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(body), "upstream_dns:")
}

func TestRunInitCreatesGitignoreWithDotSafe(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	gi, err := os.ReadFile(filepath.Join(cwd, ".gitignore"))
	require.NoError(t, err)
	require.Contains(t, string(gi), ".safe/")
}

func TestRunInitAppendsToExistingGitignoreWithoutDuplicate(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, ".gitignore"), []byte("node_modules/\n"), 0o644))
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))

	gi, _ := os.ReadFile(filepath.Join(cwd, ".gitignore"))
	s := string(gi)
	require.Contains(t, s, "node_modules/")
	require.Contains(t, s, ".safe/")
	// idempotent: second init call must not double the entry
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, true))
	gi2, _ := os.ReadFile(filepath.Join(cwd, ".gitignore"))
	require.Equal(t, 1, bytes.Count(gi2, []byte(".safe/")), "ignore entry must be added exactly once")
}

func TestRunInitUpdatesDockerignoreIfPresentButDoesNotCreate(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, runInit(&bytes.Buffer{}, cwd, false))
	_, err := os.Stat(filepath.Join(cwd, ".dockerignore"))
	require.ErrorIs(t, err, os.ErrNotExist, "must NOT create .dockerignore when absent")

	// pre-create .dockerignore, re-run init, confirm it gets updated
	cwd2 := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd2, ".dockerignore"), []byte("dist/\n"), 0o644))
	require.NoError(t, runInit(&bytes.Buffer{}, cwd2, false))
	di, _ := os.ReadFile(filepath.Join(cwd2, ".dockerignore"))
	require.Contains(t, string(di), ".safe/")
}
```

**Step 2: Run; expect FAIL**

`go test ./cmd/safe/ -run TestRunInit -v`

**Step 3: Implement**

In `cmd/safe/init.go`:

```go
// near top of file
const ignoreEntry = ".safe/"
```

Modify `runInit`:

```go
func runInit(out io.Writer, cwd string, force bool) error {
	safeDir := filepath.Join(cwd, ".safe")
	target := filepath.Join(safeDir, "safe.yaml")
	if !force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", target, err)
		}
	}
	if err := os.MkdirAll(safeDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", safeDir, err)
	}
	if err := os.WriteFile(target, []byte(initTemplate), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if err := ensureIgnoreEntry(cwd, ".gitignore", ignoreEntry, true); err != nil {
		return err
	}
	if err := ensureIgnoreEntry(cwd, ".dockerignore", ignoreEntry, false); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "wrote %s\nNext: edit the allowlist for project-specific endpoints, then run `safe --doctor`.\n", target)
	return nil
}

// ensureIgnoreEntry guarantees `entry` appears on its own line in
// <cwd>/<name>. If the file doesn't exist and createIfMissing is true,
// the file is created with just `entry`. If createIfMissing is false and
// the file is missing, ensureIgnoreEntry is a no-op. Existing lines are
// preserved; the entry is appended only if not already present (exact
// line match after Trim).
func ensureIgnoreEntry(cwd, name, entry string, createIfMissing bool) error {
	path := filepath.Join(cwd, name)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if !createIfMissing {
			return nil
		}
		return os.WriteFile(path, []byte(entry+"\n"), 0o644)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil // already present
		}
	}
	prefix := ""
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		prefix = "\n"
	}
	updated := append([]byte{}, data...)
	updated = append(updated, []byte(prefix+entry+"\n")...)
	return os.WriteFile(path, updated, 0o644)
}
```

Add imports as needed (`bytes`, `io/fs`, `strings`).

**Step 4: Verify**

`go test ./cmd/safe/ -run TestRunInit -v`

**Step 5: Commit**

```bash
git add cmd/safe/init.go cmd/safe/init_test.go
git commit -m "feat(safe): init writes .safe/safe.yaml and manages ignore files"
```

---

### Task D: `runAgent` uses `<cwd>/.safe/<runid>/` for per-run dirs

**Files:**
- Modify: `cmd/safe/run.go`:
  - Compute `runRoot := filepath.Join(cwd, ".safe", newRunID())` and `os.MkdirAll(runRoot, 0o755)`.
  - Subdirs: `configDir := filepath.Join(runRoot, "config")`, `socketDir := filepath.Join(runRoot, "socket")`.
  - `os.Mkdir(configDir, 0o755)`, `os.Mkdir(socketDir, 0o700)` (perms get tightened/widened by helpers).
  - Call `dockerrun.PrepareSocketDir(socketDir)` then `dockerrun.WriteConfigDir(configDir, configYAML)`.
  - Defer cleanup: `defer os.RemoveAll(runRoot)`.
  - Remove old calls to `dockerrun.NewSocketDir` and `dockerrun.NewConfigDir`.
  - The `runID` plumbing into `BuildArgv` is unchanged (still used for `--name safe-<runid>` etc.).

**Step 1: Update tests as needed**

`cmd/safe/run_test.go` already only tests the marshal roundtrip — should keep passing. If there are existing integration-style tests that mock the dir creation, update them. Likely none.

**Step 2: Run; expect compile failure first**

`go build ./cmd/safe/` will fail because `NewSocketDir`/`NewConfigDir` no longer exist (we replaced them in Task A).

**Step 3: Implement**

In `cmd/safe/run.go`, replace the existing per-run dir block:

```go
	runID := newRunID()
	runRoot := filepath.Join(cwd, ".safe", runID)
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		return fmt.Errorf("create run dir %s: %w", runRoot, err)
	}
	defer func() { _ = os.RemoveAll(runRoot) }()

	socketDir := filepath.Join(runRoot, "socket")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := dockerrun.PrepareSocketDir(socketDir); err != nil {
		return err
	}

	configYAML, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	configDir := filepath.Join(runRoot, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := dockerrun.WriteConfigDir(configDir, configYAML); err != nil {
		return err
	}
```

`buildDockerArgv` still takes `runID, socketDir, configDir` (or pass them via the existing positional params). `BuildArgv` is unchanged — it already accepts `SocketDir`, `ConfigDir`, `RunID`.

NOTE: `runID` was previously created inside `buildDockerArgv` via `newRunID()`. Move that creation up into `runAgent` since we now need it earlier (to build the runRoot path). Plumb it through.

**Step 4: Run all tests + lint**

`make test && make lint`

**Step 5: Commit**

```bash
git add cmd/safe/run.go
git commit -m "feat(safe): per-run state lives under <cwd>/.safe/<runid>/"
```

---

### Task E: Manual verification

**Step 1: Move existing safe.yaml**

```bash
cd /Users/rdoorn/git/safe
mkdir -p .safe
mv safe.yaml .safe/safe.yaml
```

(User-side action; document in the report.)

**Step 2: Reinstall the host binary**

```bash
make install
```

(Or `cp bin/safe /usr/local/bin/safe`.)

**Step 3: Run the failing case from the original bug report**

```bash
safe claude --help
```

**Pass criteria:**
- `safe-init: hidepid remount skipped: ...` line still present (best-effort, expected).
- `safe-fw: upstream_dns: at least one resolver required` — gone.
- `safe-init: safe-fw seed: exit status 1` — gone.
- `claude --help` reaches the terminal.

**Step 4: Verify .safe/ ignore wiring (in a scratch dir)**

```bash
mkdir /tmp/safe-init-probe && cd /tmp/safe-init-probe
/Users/rdoorn/git/safe/bin/safe init
cat .gitignore         # should contain .safe/
ls .dockerignore       # should NOT exist (we don't create it)
echo "dist/" > .dockerignore
/Users/rdoorn/git/safe/bin/safe init --force
cat .dockerignore      # should now also contain .safe/
```

**Step 5: Verify the leftover run dirs are gone after a clean exit**

```bash
ls /Users/rdoorn/git/safe/.safe/
# expected: just safe.yaml — no <runid>/ subdirs left behind
```

If a runid dir is left behind, the pre-existing `os.Exit`-skips-defer issue is biting us. Track separately; the manual fix is `rm -rf .safe/<sha-like-dir>/`.

No commit for Task E.

---

## Closing notes

- Per `[[feedback-commit-cadence]]`: 4 commits across Tasks A-D, no commit for Task E.
- Per `[[feedback-dependency-age]]`: no new deps.
- The `os.Exit`-skips-defer leak (flagged in the earlier code review) is now more visible because leftover dirs land in the user's project tree under `.safe/<runid>/` instead of `/var/folders/`. If the cleanup miss persists after merge, file a follow-up to convert `waitDocker`'s `os.Exit` into a return-and-exit-from-main pattern.
