# Container capabilities Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Unblock `safe-init` from spawning workers as different uids (it currently EPERMs on `setresuid`), and let users opt-in to extra capabilities like `SYS_ADMIN` via `safe.yaml` without source-editing.

**Architecture:**
- Hard-code the caps that SAFE's design fundamentally requires (`NET_ADMIN`, `SETUID`, `SETGID`, `KILL`) — these are non-optional; the architecture doesn't function without them.
- Add an opt-in `extra_caps []string` field to the config schema. `BuildArgv` appends `--cap-add <name>` for each entry. Validate against a small allowlist (initially `SYS_ADMIN`, `SYS_PTRACE`, `NET_BIND_SERVICE`) so users can't `extra_caps: [DAC_OVERRIDE]` themselves out of the threat model.
- Document the expanded cap set in `docs/SECURITY.md` so the threat-model is honest about what an in-container root escape now buys.

**Tech Stack:** Go 1.25, existing test patterns (testify/require). No new deps.

**Pre-flight:**
- Working dir: `/Users/rdoorn/git/safe`. Branch: `main`. Continues from `09ad16a`.
- `make test` and `make lint` start green.
- Per `[[feedback-commit-cadence]]`: commit per task.

**Out of scope:**
- Dropping the bounding-set caps inside `safe-init` after worker spawn (defense-in-depth follow-up — track separately). The current `cap-add SETUID` widens the bounding set for the agent uid too, which is a real (but bounded) threat model regression.
- Per-agent cap configuration. `extra_caps` is config-level, applies to all agents in this safe.yaml.

---

### Task F: Add SETUID/SETGID/KILL to required caps

**Files:**
- Modify: `internal/dockerrun/builder.go` — the `--cap-add` block.
- Modify: `internal/dockerrun/builder_test.go` — assert the three new caps in argv.

**Step 1: Write the failing tests**

Append to `internal/dockerrun/builder_test.go`:

```go
func TestBuildArgvIncludesRequiredCaps(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	for _, c := range []string{"NET_ADMIN", "SETUID", "SETGID", "KILL"} {
		require.Contains(t, joined, "--cap-add "+c,
			"%s must be in the required cap set: SAFE's uid-separation architecture cannot function without it", c)
	}
}
```

(Existing `TestBuildArgvHasHardeningFlags` already asserts `--cap-drop ALL` and `--cap-add NET_ADMIN` — leave those untouched.)

**Step 2: Run; expect FAIL**

`go test ./internal/dockerrun/ -run TestBuildArgvIncludesRequiredCaps -v`

**Step 3: Implement**

In `internal/dockerrun/builder.go`, replace the existing two-line cap block:

```go
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
```

with:

```go
		"--cap-drop", "ALL",
		// Required caps for SAFE's uid-separation architecture:
		//   NET_ADMIN: safe-dns manages nftables sets at runtime.
		//   SETUID/SETGID: safe-init (PID 1, root) spawns workers as
		//     uids 200/201/1000 — without these, setresuid in the child
		//     EPERMs even from root.
		//   KILL: safe-init signals cross-uid children in supervise().
		"--cap-add", "NET_ADMIN",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "KILL",
```

**Step 4: Run all builder tests**

`go test ./internal/dockerrun/ -v`
Expected: ALL pass, including existing tests.

**Step 5: Commit**

```bash
cd /Users/rdoorn/git/safe
git add internal/dockerrun/builder.go internal/dockerrun/builder_test.go
git commit -m "fix(dockerrun): add SETUID/SETGID/KILL required for uid spawn"
```

---

### Task G: Optional `extra_caps` field in safe.yaml

**Files:**
- Modify: `internal/config/config.go` — add `ExtraCaps []string` to `Config` with `yaml:"extra_caps"`.
- Modify: `internal/config/validate.go` — add `validateExtraCaps`.
- Modify: `internal/config/validate_test.go` — cover the new validator.
- Modify: `internal/dockerrun/builder.go` — read `in.Config.ExtraCaps`, append `--cap-add <name>` for each.
- Modify: `internal/dockerrun/builder_test.go` — test that extra caps are appended.
- Modify: `cmd/safe/init.go` — add commented-out `extra_caps:` block to the template with the SYS_ADMIN example.
- Modify: `internal/config/loader_test.go`, `cmd/safe/printconfig_test.go` — ensure they don't break when the new field is empty.

**Step 1: Write the validator test (red)**

Append to `internal/config/validate_test.go`:

```go
func TestValidateExtraCapsAllowedNames(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ExtraCaps = []string{"SYS_ADMIN"}
	require.NoError(t, config.Validate(cfg, "claude"))
}

func TestValidateExtraCapsRejectsUnknown(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ExtraCaps = []string{"DAC_OVERRIDE"}
	err := config.Validate(cfg, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra_caps")
	require.Contains(t, err.Error(), "DAC_OVERRIDE")
}

func TestValidateExtraCapsRejectsLowercase(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ExtraCaps = []string{"sys_admin"}
	err := config.Validate(cfg, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra_caps")
}

func TestValidateExtraCapsRejectsCAP_Prefix(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ExtraCaps = []string{"CAP_SYS_ADMIN"} // docker accepts both forms; pick one and enforce
	err := config.Validate(cfg, "claude")
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra_caps")
}
```

(If `validBaseConfig` doesn't exist as a helper in validate_test.go, look at the existing test pattern and use whatever constructor the existing tests use. Adapt the name accordingly.)

**Step 2: Write the BuildArgv test (red)**

Append to `internal/dockerrun/builder_test.go`:

```go
func TestBuildArgvAppendsExtraCaps(t *testing.T) {
	cfg := minimalConfig()
	cfg.ExtraCaps = []string{"SYS_ADMIN", "SYS_PTRACE"}
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.Contains(t, joined, "--cap-add SYS_ADMIN")
	require.Contains(t, joined, "--cap-add SYS_PTRACE")
}

func TestBuildArgvNoExtraCapsByDefault(t *testing.T) {
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    minimalConfig(),
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		SocketDir: "/tmp/safe-x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	require.NotContains(t, joined, "--cap-add SYS_ADMIN",
		"extra caps must be opt-in only")
	require.NotContains(t, joined, "--cap-add SYS_PTRACE")
}
```

**Step 3: Run; expect FAIL**

`go test ./internal/config/ ./internal/dockerrun/ -run 'TestValidateExtraCaps|TestBuildArgvAppendsExtraCaps|TestBuildArgvNoExtraCapsByDefault' -v`

**Step 4: Implement schema**

In `internal/config/config.go`, add to the `Config` struct (alongside the other top-level fields):

```go
	ExtraCaps      []string         `yaml:"extra_caps"`
```

**Step 5: Implement validator**

In `internal/config/validate.go`, add:

```go
// allowedExtraCaps is the deliberately small allowlist of optional
// container capabilities a user may add via extra_caps. Anything else
// has to be source-edited so a misconfigured config can't widen the
// container's bounding set into a sudden privilege-escalation surface.
//
//   SYS_ADMIN: enables /proc hidepid=2 remount (see safe-init).
//   SYS_PTRACE: lets a debugger attach across uids inside the container
//     (advanced/diagnostic only).
//   NET_BIND_SERVICE: binds privileged ports (<1024) — rarely needed,
//     since safe-dns binds 127.0.0.1:53 via Docker's default unprivileged
//     port range, but listed for completeness.
var allowedExtraCaps = map[string]struct{}{
	"SYS_ADMIN":        {},
	"SYS_PTRACE":       {},
	"NET_BIND_SERVICE": {},
}

func validateExtraCaps(caps []string) error {
	for _, c := range caps {
		if _, ok := allowedExtraCaps[c]; !ok {
			return fmt.Errorf("extra_caps: %q is not allowed (allowed: SYS_ADMIN, SYS_PTRACE, NET_BIND_SERVICE)", c)
		}
	}
	return nil
}
```

Call `validateExtraCaps` from `Validate`, after the existing checks:

```go
	if err := validateExtraCaps(c.ExtraCaps); err != nil {
		return err
	}
```

**Step 6: Implement BuildArgv plumbing**

In `internal/dockerrun/builder.go`, AFTER the hard-coded `--cap-add KILL` line (from Task F), append a loop:

```go
	for _, c := range in.Config.ExtraCaps {
		argv = append(argv, "--cap-add", c)
	}
```

Insert this BEFORE the `--read-only` flag (which is the next item in the current argv build).

**Step 7: Run; expect GREEN**

`go test ./internal/config/ ./internal/dockerrun/ -v`

**Step 8: Update init template**

In `cmd/safe/init.go`, in the `initTemplate` constant, ADD this commented block in a sensible location (after `env_passthrough:` is a good spot, before `# Docker resource limits.`):

```yaml
# Opt-in extra Linux capabilities granted to the container. Allowed:
#   SYS_ADMIN        — enables /proc hidepid=2 (hides other uids' PIDs
#                      from the agent uid).
#   SYS_PTRACE       — diagnostic only; lets a debugger attach across
#                      uids inside the container.
#   NET_BIND_SERVICE — bind privileged ports inside the container.
# Anything not on this list must be source-edited; see internal/config/validate.go.
# extra_caps: []
```

**Step 9: Confirm existing tests still green**

`make test`
Expected: all pass, including loader/printconfig tests (the new field is empty by default, doesn't break serialization).

**Step 10: Commit**

```bash
cd /Users/rdoorn/git/safe
git add internal/config/config.go internal/config/validate.go internal/config/validate_test.go internal/dockerrun/builder.go internal/dockerrun/builder_test.go cmd/safe/init.go
git commit -m "feat(config): extra_caps field for optional capabilities"
```

---

### Task H: Document the cap expansion in SECURITY.md

**Files:**
- Modify: `docs/SECURITY.md` — find the section that lists container caps (or the threat-model table) and update.

**Step 1: Read the current SECURITY.md**

`cat docs/SECURITY.md` from `/Users/rdoorn/git/safe`. Find the lines that mention `NET_ADMIN` or `cap-drop`/`cap-add` or the threat-model table about "Agent escapes to root".

**Step 2: Update**

Replace the cap-list paragraph with text that accurately reflects:
- Required caps: `NET_ADMIN`, `SETUID`, `SETGID`, `KILL`.
- Why each is needed (one sentence per cap; mirror the in-code comment from Task F).
- Threat model adjustment: an attacker who escapes to in-container root now has `CAP_SETUID` in the bounding set, meaning they could (in principle) `setuid` to keyholder uid 201 and try to read the keyholder process memory — BUT `hidepid` (if enabled via `SYS_ADMIN`) + seccomp `ptrace`/`process_vm_*` denial still prevent reading the secret. Without `SYS_ADMIN`, hidepid is best-effort and an attacker who escapes to keyholder uid can read `/proc/self/mem` — but they're already inside the keyholder uid, so they get the secret anyway. Net: container-root escape was always game-over; the cap expansion doesn't materially change that.
- Add a note: `SYS_ADMIN` via `extra_caps` enables `hidepid=2` and strengthens the in-container isolation; recommended for production use.

**Step 3: Commit**

```bash
cd /Users/rdoorn/git/safe
git add docs/SECURITY.md
git commit -m "docs(security): document expanded container cap set"
```

---

### Task I: Manual end-to-end verification

**Step 1: Reinstall the host binary**

```bash
cd /Users/rdoorn/git/safe
make install
```

**Step 2: Verify the original `safe claude` failure is gone**

```bash
safe claude --help
```

**Pass criteria:**
- `safe-init: hidepid remount skipped: ...` still present (best-effort; needs SYS_ADMIN to fix).
- `safe-init: add --cap-add SYS_ADMIN to docker run to enable PID hiding` still present.
- `safe-init: start safe-dns: ... operation not permitted` — **GONE**.
- `claude --help` output reaches your terminal.

**Step 3: Optionally enable SYS_ADMIN via extra_caps and re-verify**

Edit `.safe/safe.yaml`, uncomment / add:

```yaml
extra_caps:
  - SYS_ADMIN
```

Re-run `safe claude --help`. The `hidepid remount skipped` line should NOW be GONE — hidepid succeeded.

**Step 4: Negative check on the allowlist**

Edit `.safe/safe.yaml`, set `extra_caps: [DAC_OVERRIDE]`. Run `safe claude --help`. Expected: host CLI errors with `extra_caps: "DAC_OVERRIDE" is not allowed (...)`. Revert.

No commit.

---

## Closing notes

- Per `[[feedback-commit-cadence]]`: 3 commits across Tasks F-H, no commit for Task I.
- Per `[[feedback-dependency-age]]`: no new deps.
- The pre-existing `os.Exit`-skips-defer leak still applies — leftover `<runid>/` dirs under `.safe/` after any non-zero exit. Track in a follow-up.
- Defense-in-depth follow-up: have `safe-init` drop `SETUID`/`SETGID`/`KILL` from the bounding set via `PR_CAPBSET_DROP` AFTER spawning the keyholder + agent. That eliminates the bounding-set widening exposed to the agent uid. Track separately.
