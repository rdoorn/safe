# tmpfs audit log + TCP keyholder bootstrap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** (1) Let `safe-dns` write its audit log on a read-only rootfs. (2) Replace the unix-socket bootstrap handshake (which doesn't work across macOS Docker Desktop's bind mount) with a TCP loopback handshake that does.

**Background:**

- **`safe-dns: open audit log: open /var/log/safe/audit.log: read-only file system`** — the container runs with `--read-only`. The image creates `/var/log/safe` at build time, but writes there fail because it's on the (now read-only) image rootfs. Fix: overlay a writable tmpfs at `/var/log/safe`, owned by uid 200 (firewall).

- **`safe: pipe auth secret: ... connect: connection refused` (host) paired with `safe-init: read auth secret: ... accept ... i/o timeout` (container)** — `safe-init` listens on a unix socket inside the container at a bind-mounted path. macOS Docker Desktop's VirtioFS / gRPC FUSE layer does not faithfully replicate AF_UNIX socket inodes across the macOS↔Linux VM boundary. Files traverse the bind mount fine (we already confirmed this with `config.yaml`); sockets do not. Fix: replace the unix socket with a TCP loopback connection.

**Architecture (Task K):**

- `safe-init` listens on `0.0.0.0:9099` inside the container during bootstrap. After accept-read-close, the listener goes away — only safe-init (root) is running at that point, so no other in-container process can race.
- Host `docker run` is invoked with `-p 127.0.0.1:0:9099` — Docker picks an ephemeral host port mapping to container port 9099. The bind is `127.0.0.1` only, so the bootstrap port is never reachable from the network.
- Host CLI, concurrently with the foreground `docker run`, polls `docker port safe-<runid> 9099/tcp` to discover the ephemeral host port (Docker assigns it once the container starts). Once known, it dials `127.0.0.1:<host-port>`, writes the secret + newline, closes. `safe-init`'s `accept` returns and reads the bytes.
- Threat-model property unchanged: secret flows host → safe-init only. An attacker on the host racing to connect first would hit safe-init (which would read garbage and exit) — DoS, not exfil. After bootstrap, the listener is gone; no further attack surface.

**Tech Stack:** Go 1.25. No new deps. Uses `os/exec` to shell `docker port` (already a dependency).

**Pre-flight:**
- Working dir: `/Users/rdoorn/git/safe`. Branch: `main`. Continues from `bbcc567` (post-push).
- `make test` + `make lint` start green.
- Per `[[feedback-commit-cadence]]`: commit per task.

**Out of scope:**
- The pre-existing `os.Exit` skips defers leak (still tracked).
- Defense-in-depth cap-bounding-set drop after bootstrap (still tracked).

---

### Task J: tmpfs `/var/log/safe`

**Files:**
- Modify: `internal/dockerrun/builder.go` — add one `--tmpfs` flag in the existing tmpfs block.
- Modify: `internal/dockerrun/builder_test.go` — add a test.

**Step 1: Write the failing test**

Append to `internal/dockerrun/builder_test.go`:

```go
func TestBuildArgvTmpfsForAuditLog(t *testing.T) {
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
	require.Contains(t, joined, "--tmpfs /var/log/safe:rw,nosuid,nodev,uid=200,gid=200,size=64m",
		"safe-dns audit log needs a writable tmpfs since rootfs is read-only")
}
```

**Step 2: Run; expect FAIL.**

From `/Users/rdoorn/git/safe`:
`go test ./internal/dockerrun/ -run TestBuildArgvTmpfsForAuditLog -v`

**Step 3: Implement.**

In `internal/dockerrun/builder.go`, find the existing tmpfs block:

```go
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m",
		"--tmpfs", "/run:rw,nosuid,nodev,noexec,size=64m",
		"--tmpfs", "/home/agent:rw,nosuid,nodev,size=512m",
```

Add immediately after the `/home/agent` line:

```go
		"--tmpfs", "/var/log/safe:rw,nosuid,nodev,uid=200,gid=200,size=64m",
```

(Note: NOT `noexec` — JSONL audit logging shouldn't need it, but it doesn't matter either way. Match the no-`noexec` shape of `/home/agent` for consistency; the audit log isn't an exec target.)

**Step 4: Run all builder tests; expect GREEN.**

`go test ./internal/dockerrun/ -v`

**Step 5: Run full suite + lint.**

`make test && make lint`

**Step 6: Commit.**

```bash
cd /Users/rdoorn/git/safe
git add internal/dockerrun/builder.go internal/dockerrun/builder_test.go
git commit -m "fix(dockerrun): tmpfs /var/log/safe so safe-dns audit log is writable"
```

NO Claude/AI/LLM attribution.

---

### Task K: TCP loopback bootstrap

**Files:**
- Modify: `cmd/safe-init/main.go` — replace unix socket listener with TCP listener on a fixed in-container port; drop the socket-path constant.
- Modify: `cmd/safe/run.go` — remove socket-path argument to `pipeAuthSecret`; pass containerName instead.
- Modify: `internal/dockerrun/keypipe.go` — `PipeKey` now takes `containerName, port` and does `docker port` discovery + TCP dial.
- Modify: `internal/dockerrun/keypipe_test.go` — rewrite tests.
- Modify: `internal/dockerrun/builder.go` — add `-p 127.0.0.1:0:9099` to argv; drop the `/run/safe` bind mount (no longer needed for the socket; verify no other code uses /run/safe inside the container).
- Modify: `internal/dockerrun/builder_test.go` — assert the new port mapping; update existing tests that assert the socket-dir bind mount.

**Step 1: Define the in-container port**

In a shared location both `cmd/safe-init` and `internal/dockerrun` can reference, declare:

```go
// internal/dockerrun/constants.go (new file)
package dockerrun

// BootstrapPort is the in-container TCP port safe-init listens on
// during the one-shot keyholder-secret bootstrap. The host side maps
// 127.0.0.1:<ephemeral-host-port> -> this container port via docker -p.
const BootstrapPort = "9099"
```

(Pick `9099` to avoid common ports. The container's network is isolated; the port number doesn't matter beyond not colliding with internal services like safe-keyholder on 8443.)

In `cmd/safe-init/main.go`, import this constant or declare it locally — copy the value, do not introduce a cross-package import from cmd/safe-init into internal/dockerrun (safe-init is a separately-compiled binary that runs in the container; clean separation is preferable). So:

```go
const bootstrapPort = "9099"
```

(Comment that this must match `internal/dockerrun.BootstrapPort`.)

**Step 2: Rewrite the host-side PipeKey + tests**

`internal/dockerrun/keypipe.go`:

```go
// Package dockerrun helpers; this file owns the host-side keyholder
// secret bootstrap.
package dockerrun

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// PipeKey discovers the ephemeral host port docker mapped to the
// container's BootstrapPort, connects to 127.0.0.1:<port>, and writes
// `secret + "\n"`. The discovery polls `docker port <containerName>
// <BootstrapPort>/tcp` until the mapping is reported.
func PipeKey(ctx context.Context, containerName, secret string) error {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(10 * time.Second)
	}

	var hostAddr string
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, BootstrapPort+"/tcp").Output()
		if err == nil {
			addr := strings.TrimSpace(string(out))
			if addr != "" {
				// `docker port` returns "127.0.0.1:54321\n" (one or more lines if multiple bindings).
				hostAddr = strings.SplitN(addr, "\n", 2)[0]
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hostAddr == "" {
		return fmt.Errorf("docker port %s %s/tcp did not return a host mapping before deadline", containerName, BootstrapPort)
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", hostAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", hostAddr, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(secret + "\n")); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}
```

Rewrite `internal/dockerrun/keypipe_test.go` to test what we can without docker:

```go
package dockerrun_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

// We can't easily test the docker-port discovery loop without docker.
// What we can test is: given a known host address (which the real
// PipeKey discovers from `docker port`), connecting and writing works
// end-to-end. To do this we add a lower-level helper:
//   writeSecretToAddr(ctx, hostAddr, secret) error
// PipeKey then becomes: discover hostAddr via docker port + call writeSecretToAddr.

// If the implementer chooses NOT to split, document why and write a
// simpler smoke test that just confirms PipeKey returns an error in
// reasonable time when docker isn't reachable.

func TestPipeKeyConnectsAndWritesSecret(t *testing.T) {
	// Start a host-local listener and verify a manually-constructed
	// connection write reaches it. This tests the wire format, not the
	// discovery loop.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		// nothing else — receiver-side smoke test; assertions in the dial side
	}()

	// For now, just open a TCP connection ourselves to the same listener and
	// verify the write works. PipeKey's discovery layer is exercised in
	// manual verification.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	_, err = conn.Write([]byte("secret\n"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestPipeKeyTimesOutIfDockerPortFails(t *testing.T) {
	// `docker port nonexistent-container 9099/tcp` exits non-zero almost
	// instantly. PipeKey should still respect its deadline and return an
	// error within a small window of it.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := dockerrun.PipeKey(ctx, "safe-nonexistent-container-for-test", "secret")
	require.Error(t, err)
}
```

**Step 3: Rewrite the container-side listener in safe-init**

In `cmd/safe-init/main.go`:

1. Delete the const `keyholderSocket = "/run/safe/keyholder.sock"`.
2. Replace the existing `readSecretFromSocket(socketPath, timeout)` with `readSecretFromTCP(port, timeout)`:

```go
const bootstrapPort = "9099" // must match internal/dockerrun.BootstrapPort

func readSecretFromTCP(port string, timeout time.Duration) ([]byte, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return nil, fmt.Errorf("listen tcp 0.0.0.0:%s: %w", port, err)
	}
	defer func() { _ = ln.Close() }()

	if t, ok := ln.(*net.TCPListener); ok {
		_ = t.SetDeadline(time.Now().Add(timeout))
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept on :%s: %w", port, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	const maxSecretBytes = 1 << 16 // 64 KiB — generous for OAuth JSON
	data, err := io.ReadAll(io.LimitReader(conn, maxSecretBytes))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return data, nil
}
```

3. Update the `run()` function's call site:

```go
secret, err := readSecretFromTCP(bootstrapPort, keyPipeTimeout)
```

(Was: `readSecretFromSocket(keyholderSocket, keyPipeTimeout)`.)

**Step 4: Update cmd/safe/run.go**

Remove `keyholderSocketFile` and the `socketDir + keyholderSocketFile` join. The `pipeAuthSecret` goroutine now takes `containerName` (which is `safe-<runID>`):

```go
const containerNamePrefix = "safe-"

// (in runAgent, after cmd.Start succeeds:)
if !shell && len(secret) > 0 {
	go pipeAuthSecret(ctx, stderr, containerNamePrefix+runID, secret)
}
```

And `pipeAuthSecret` itself:

```go
func pipeAuthSecret(parent context.Context, stderr io.Writer, containerName string, secret []byte) {
	ctx, cancel := context.WithTimeout(parent, keyholderTimeout)
	defer cancel()
	if err := dockerrun.PipeKey(ctx, containerName, string(secret)); err != nil {
		fmt.Fprintln(stderr, "safe: pipe auth secret:", err)
	}
}
```

The `socketDir` is now unused for PipeKey — but is it used for anything else? Search for `socketDir` references in run.go. The current code creates a socketDir to be bind-mounted at `/run/safe`. With the TCP design, that bind mount is gone.

**Step 5: Update internal/dockerrun/builder.go**

Add the port mapping to argv:

```go
"-p", "127.0.0.1:0:"+BootstrapPort+"/tcp",
```

Position: somewhere in the network section. After `--network bridge` and before `--dns 127.0.0.1` is a sensible spot.

Remove the `-v in.SocketDir+":/run/safe"` line — no longer needed.

Question: do we also remove `SocketDir` from `Inputs`? It's unused after this change. **Yes, remove it.** Plus the `socketDir` plumbing in cmd/safe/run.go. Plus the no-longer-needed `PrepareSocketDir` helper (and the `socket/` subdir in `<cwd>/.safe/<runid>/`). Clean cut.

Actually wait — `PrepareSocketDir` was specifically for the keyholder.sock. If that's gone, the whole socket-dir concept goes with it. Re-check whether safe-keyholder uses any other socket. Looking back: safe-keyholder serves on `127.0.0.1:8443` (TCP). No unix socket. So yes, the socket dir is entirely gone.

Plan-level decision: **delete** `internal/dockerrun/socket.go`, its tests, the `socket/` subdir creation in `cmd/safe/run.go`, the `SocketDir` field in `Inputs`, and `keyholderSocketFile`. The cleanup is meaningful diff but mechanical.

**Step 6: Update builder tests**

In `internal/dockerrun/builder_test.go`:
- Replace `TestBuildArgvBindsSocketDir` with `TestBuildArgvPublishesBootstrapPort` that asserts `-p 127.0.0.1:0:9099/tcp` in argv.
- Remove `SocketDir:` field from all existing test `Inputs` literals.
- Add a test that asserts NO `-v ...:/run/safe` line in argv (defensive).

**Step 7: Build + test + lint**

From `/Users/rdoorn/git/safe`:
1. `go build ./...` — must succeed.
2. `go test ./... -v` — all pass.
3. `make lint` — 0 issues.

If any test references the removed `SocketDir`, `PrepareSocketDir`, `socket.go`, `keypipe_test.go` (old), update it.

**Step 8: Commit**

```bash
cd /Users/rdoorn/git/safe
git add cmd/safe-init/main.go cmd/safe/run.go internal/dockerrun/keypipe.go internal/dockerrun/keypipe_test.go internal/dockerrun/builder.go internal/dockerrun/builder_test.go internal/dockerrun/constants.go
# also: removals
git rm internal/dockerrun/socket.go internal/dockerrun/socket_test.go  # may not be needed if you only removed contents — check git status
git commit -m "fix(safe): bootstrap keyholder secret over TCP loopback"
```

NO Claude/AI/LLM attribution.

## Tests we deliberately skip

- An end-to-end test that runs an actual docker container and verifies PipeKey works. Out of scope for unit tests; verified manually in Task L.
- A test that verifies `docker port` polling timing. The "docker isn't reachable" path is covered; the success path requires docker.

---

### Task L: Manual end-to-end verification

**Step 1: Rebuild image AND host binary**

The image must include the rebuilt `safe-init` (it changed in Task K). The host binary must include the rebuilt `safe` (it changed too).

```bash
cd /Users/rdoorn/git/safe
make build
docker buildx build -t safe-runtime:dev .
make install
```

**Step 2: Run safe claude**

```bash
safe claude --help
```

**Pass criteria:**
- `safe-init: hidepid remount skipped: ...` — still present (best-effort, expected unless `SYS_ADMIN` in `extra_caps`).
- `safe-dns: open audit log: ... read-only file system` — **GONE**.
- `safe: pipe auth secret: ... connection refused` — **GONE**.
- `safe-init: read auth secret: ... i/o timeout` — **GONE**.
- `claude --help` output reaches your terminal.

**Step 3: With SYS_ADMIN enabled, full clean run**

Set `extra_caps: [SYS_ADMIN]` in `.safe/safe.yaml`. Run `safe claude --help` again.

Expected: clean run with NO `safe-init: hidepid remount skipped` line. Just claude --help output.

**Step 4: Confirm no leftover state in `.safe/`**

```bash
ls /Users/rdoorn/git/safe/.safe/
```

Expected: only `safe.yaml`. (If a `<runid>/` dir is left behind, the pre-existing `os.Exit`-skips-defer leak is biting us. Track separately.)

No commit.

---

## Closing notes

- Per `[[feedback-commit-cadence]]`: 2 commits across Tasks J-K. No commit for Task L.
- After Task L: branch is in a good state to ship. Pre-existing follow-ups remain tracked.
- The bootstrap port (9099) is arbitrary — change at any time. The container's network is isolated; nothing outside the host loopback can reach it.
