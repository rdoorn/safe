# SAFE: Fix flaky :9099 timeout + broken shift+enter

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the intermittent `accept on :9099: i/o timeout` failure on macOS Docker Desktop, and make shift+enter insert a newline in `safe claude` the same way it does in bare `claude`.

**Architecture:**

- **Bug 1 (:9099 timeout):** Docker Desktop's vpnkit/gRPC port forwarder accepts the host-side TCP connection BEFORE the in-container listener is ready, swallows the host's `write()`, then closes when it can't forward. On Linux iptables-DNAT this would `ECONNREFUSED` and the host would retry, but on Docker Desktop the write returns OK and bytes are silently dropped. Fix in two layers: (a) move `net.Listen` to the very first line of `safe-init.run()` so the listener exists before the host can possibly write, (b) add a one-way READY handshake — container writes `SAFE-INIT-READY\n` on accept, host reads it before writing the secret, retries the dial on read failure. (a) shrinks the window; (b) closes it entirely because the host only writes after confirming end-to-end delivery via a return-trip byte.

- **Bug 2 (shift+enter):** claude code reads `TERM_PROGRAM` / `COLORTERM` to decide whether to enable the kitty keyboard protocol, which is what makes shift+enter distinguishable from enter (otherwise both arrive as `\r` and there's no way for the app to tell them apart). The default `env_passthrough` in safe.yaml is `[TERM, LANG, TZ]` — missing `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, `COLORTERM`. Fix: bake these terminal-identification vars into a code-level always-on list in `internal/dockerrun`, augmenting whatever the user's YAML configured. Existing user configs pick up the fix automatically; the template gets updated for new users.

**Tech Stack:** Go 1.25, testify, docker. No new deps.

**Pre-flight:**
- Working dir: project root. Branch: a new branch off `main`. Per project CLAUDE.md: one commit per task.
- `make test` + `make lint` must start green; verify with `make test lint` before Task 1.
- After all tasks, manually test on macOS Docker Desktop: run `safe claude` 10 times in a row and confirm zero timeouts; inside `safe claude`, press shift+enter and confirm a newline is inserted instead of submit.

**Out of scope:**
- Changing the bootstrap from TCP to docker stdin or FIFO. The TCP design (per `docs/plans/2026-05-18-tcp-bootstrap.md`) stays; we only add a handshake on top.
- Any change to the secret format on the wire (still `secret + "\n"`).
- Anything related to bracketed-paste handling beyond what TERM_PROGRAM enables in claude.

---

## Task 1: Container writes `SAFE-INIT-READY\n` on accept, before reading the secret

**Files:**
- Modify: `cmd/safe-init/main.go:421-449` — `readSecretFromTCP`
- Modify: `cmd/safe-init/main_test.go` — add a test for the handshake

The handshake byte is a single fixed ASCII line. It is NOT a credential (an attacker on the bridge network seeing it learns nothing); it's purely a "the in-container listener really did accept this connection" marker for the host to verify end-to-end delivery.

- [ ] **Step 1: Write the failing test**

Append to `cmd/safe-init/main_test.go`:

```go
import (
	"net"
	"strings"
	"sync"
	"time"
)

const safeInitReadyLine = "SAFE-INIT-READY\n"

// readSecretFromTCP must write SAFE-INIT-READY\n to the accepted
// connection BEFORE it reads the secret. This is the host's signal
// that the in-container listener really accepted the connection
// (rather than vpnkit accepting on the host side and dropping bytes).
func TestReadSecretFromTCPWritesReadyBeforeRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strings.Split(ln.Addr().String(), ":")[1]
	require.NoError(t, ln.Close())

	var got []byte
	var readyLine string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give the listener a moment to come up.
		time.Sleep(50 * time.Millisecond)
		conn, derr := net.Dial("tcp", "127.0.0.1:"+port)
		require.NoError(t, derr)
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(safeInitReadyLine))
		_, rerr := conn.Read(buf)
		require.NoError(t, rerr)
		readyLine = string(buf)
		_, werr := conn.Write([]byte("my-secret\n"))
		require.NoError(t, werr)
	}()

	data, err := readSecretFromTCP(port, 2*time.Second)
	require.NoError(t, err)
	got = data
	wg.Wait()

	require.Equal(t, safeInitReadyLine, readyLine, "READY line must be sent before secret read")
	require.Equal(t, "my-secret\n", string(got))
}
```

- [ ] **Step 2: Run; expect FAIL**

```
go test ./cmd/safe-init/... -run TestReadSecretFromTCPWritesReadyBeforeRead -v
```

Expected: FAIL — the test client times out reading the READY bytes because the current `readSecretFromTCP` jumps straight to `io.ReadAll`.

- [ ] **Step 3: Add the handshake to `readSecretFromTCP`**

Above the existing `readSecretFromTCP` add the constant:

```go
// safeInitReadyLine is the one-way handshake byte the in-container
// listener writes immediately after accept, before reading the secret.
// The host's PipeKey reads this to confirm the connection really
// reached safe-init (vs being held open by docker-proxy / vpnkit while
// the listener didn't exist yet). The content is not sensitive.
const safeInitReadyLine = "SAFE-INIT-READY\n"
```

Replace the body of `readSecretFromTCP` (`cmd/safe-init/main.go:426-449`) with:

```go
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

	// Write the READY line BEFORE reading the secret. The host's
	// PipeKey reads this round-trip byte and only proceeds to write
	// the secret if it succeeds. This kills the macOS Docker Desktop
	// race where vpnkit accepts the host TCP connection before this
	// listener exists, swallows the host's write(), and silently drops
	// the bytes.
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, werr := conn.Write([]byte(safeInitReadyLine)); werr != nil {
		return nil, fmt.Errorf("write ready: %w", werr)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	const maxSecretBytes = 1 << 16 // 64 KiB — generous for OAuth JSON
	data, err := io.ReadAll(io.LimitReader(conn, maxSecretBytes))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return data, nil
}
```

- [ ] **Step 4: Run; expect PASS**

```
go test ./cmd/safe-init/... -run TestReadSecretFromTCPWritesReadyBeforeRead -v
```

Expected: PASS.

- [ ] **Step 5: Run full test + lint to verify nothing else broke**

```
make test lint
```

Expected: green. (The existing `TestRawTCPSecretDelivery` in keypipe_test.go is NOT exercising `readSecretFromTCP`; it's a manual TCP round-trip test, so it stays untouched until Task 2.)

- [ ] **Step 6: Commit**

```
git add cmd/safe-init/main.go cmd/safe-init/main_test.go
git commit -m "feat: safe-init writes SAFE-INIT-READY before reading bootstrap secret"
```

---

## Task 2: Open the bootstrap listener BEFORE config load

**Files:**
- Modify: `cmd/safe-init/main.go:81-111` — `run()` opens the listener first
- Modify: `cmd/safe-init/main.go:421-...` — split `readSecretFromTCP` into `openSecretListener` + `acceptAndReadSecret`

Right now, `safe-init.run()` does `LoadFile` → `resolveAuthMode` → `Listen`. On Docker Desktop, the `/etc/safe/config.yaml` bind mount has multi-second cold-read latency, so the listener can come up several seconds after the container's network is exposed. Task 1's handshake closes the actual race, but moving the listen earlier is still worth doing: it shrinks the window where the host has to keep retrying, so the common-case latency drops back to ~0ms.

- [ ] **Step 1: Write the failing test**

Append to `cmd/safe-init/main_test.go`:

```go
// openSecretListener must bind the port WITHOUT blocking on accept,
// so callers can listen-then-load-config and only accept once they're
// ready. The returned listener is closed by the caller.
func TestOpenSecretListenerBindsSynchronously(t *testing.T) {
	ln, err := openSecretListener("0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	// Port should be a real bound port (0 means "kernel pick one").
	addr := ln.Addr().String()
	require.NotEmpty(t, addr)
	require.Contains(t, addr, "[::]:")
}

// acceptAndReadSecret reads a secret from an externally-opened listener,
// performing the SAFE-INIT-READY handshake before the read.
func TestAcceptAndReadSecretPerformsHandshake(t *testing.T) {
	ln, err := openSecretListener("0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := strings.Split(ln.Addr().String(), ":")[len(strings.Split(ln.Addr().String(), ":"))-1]

	var readyLine string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		conn, derr := net.Dial("tcp", "127.0.0.1:"+port)
		require.NoError(t, derr)
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(safeInitReadyLine))
		_, rerr := conn.Read(buf)
		require.NoError(t, rerr)
		readyLine = string(buf)
		_, _ = conn.Write([]byte("secret-bytes\n"))
	}()

	data, err := acceptAndReadSecret(ln, 2*time.Second)
	require.NoError(t, err)
	wg.Wait()
	require.Equal(t, safeInitReadyLine, readyLine)
	require.Equal(t, "secret-bytes\n", string(data))
}
```

- [ ] **Step 2: Run; expect FAIL (undefined: openSecretListener, acceptAndReadSecret)**

```
go test ./cmd/safe-init/... -run "TestOpenSecretListenerBindsSynchronously|TestAcceptAndReadSecretPerformsHandshake" -v
```

Expected: FAIL — compile error, undefined symbols.

- [ ] **Step 3: Split `readSecretFromTCP` into two functions**

In `cmd/safe-init/main.go`, REPLACE the entire `readSecretFromTCP` function with these two:

```go
// openSecretListener binds the bootstrap port without accepting.
// Callers do this as the FIRST thing in safe-init.run() so the
// listener exists before docker exposes the port mapping; otherwise
// macOS Docker Desktop's vpnkit can accept on the host side, fail to
// forward, and silently drop the host's write. After binding, the
// caller is free to do other work (config load, auth-mode resolution,
// etc.) and call acceptAndReadSecret when ready.
func openSecretListener(port string) (net.Listener, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return nil, fmt.Errorf("listen tcp 0.0.0.0:%s: %w", port, err)
	}
	return ln, nil
}

// acceptAndReadSecret accepts ONE connection on ln, writes the
// SAFE-INIT-READY handshake byte, then reads the secret until EOF
// (up to 64 KiB). Closes the listener and connection before returning.
// See safeInitReadyLine doc for the handshake's purpose.
func acceptAndReadSecret(ln net.Listener, timeout time.Duration) ([]byte, error) {
	defer func() { _ = ln.Close() }()

	if t, ok := ln.(*net.TCPListener); ok {
		_ = t.SetDeadline(time.Now().Add(timeout))
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept on %s: %w", ln.Addr(), err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, werr := conn.Write([]byte(safeInitReadyLine)); werr != nil {
		return nil, fmt.Errorf("write ready: %w", werr)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	const maxSecretBytes = 1 << 16 // 64 KiB — generous for OAuth JSON
	data, err := io.ReadAll(io.LimitReader(conn, maxSecretBytes))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return data, nil
}

// readSecretFromTCP is kept as a thin shim so the old single-call
// path still works (used by Task 1's test and by any caller that
// doesn't need to listen-then-do-other-work). New code should call
// openSecretListener + acceptAndReadSecret directly.
func readSecretFromTCP(port string, timeout time.Duration) ([]byte, error) {
	ln, err := openSecretListener(port)
	if err != nil {
		return nil, err
	}
	return acceptAndReadSecret(ln, timeout)
}
```

- [ ] **Step 4: Reorder `run()` so the listener opens first**

In `cmd/safe-init/main.go`, REPLACE the block from the start of `run()` (line 81) down through the existing `if keyholderEnabled { ... readSecretFromTCP ... }` block with:

```go
func run(agentName string, agentArgs []string) error { //nolint:gocyclo // linear init pipeline with best-effort skip branches; splitting hurts readability
	logStage := func(stage int, msg string) {
		fmt.Fprintf(os.Stderr, "safe-init: stage=%d %s\n", stage, msg)
	}

	// Bootstrap-secret listener MUST be opened before any other work.
	// Docker exposes the host port mapping as soon as the container
	// starts; if the host CLI's PipeKey connects and the in-container
	// listener doesn't exist yet, docker-proxy / vpnkit accepts the
	// host TCP and (on macOS) swallows the bytes. Bind first, then do
	// everything else, then accept when we have the secret to feed.
	// Task 1's READY handshake closes the remaining race; this early-
	// bind narrows the window so the host's retry loop almost never
	// needs to fire.
	var secretLn net.Listener
	if keyholderEnabled {
		logStage(0, "open bootstrap listener (FIRST; before any other work)")
		ln, lerr := openSecretListener(bootstrapPort)
		if lerr != nil {
			return fmt.Errorf("open bootstrap listener: %w", lerr)
		}
		secretLn = ln
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		if secretLn != nil {
			_ = secretLn.Close()
		}
		return fmt.Errorf("load config: %w", err)
	}

	var secret []byte
	authMode := ""
	if keyholderEnabled {
		logStage(1, "accept + read bootstrap secret")
		var ferr error
		authMode, ferr = resolveAuthMode(cfg, agentName)
		if ferr != nil {
			_ = secretLn.Close()
			return fmt.Errorf("determine auth mode: %w", ferr)
		}
		s, rerr := acceptAndReadSecret(secretLn, keyPipeTimeout)
		if rerr != nil {
			return fmt.Errorf("read auth secret: %w", rerr)
		}
		secret = s
	}
```

Then renumber the subsequent `logStage(N, ...)` calls so they remain contiguous (logStage(2, "remount /proc..."), logStage(3, ...) etc — currently line 113 is `logStage(1, "remount /proc hidepid=2 ...")` which becomes `logStage(2, ...)`). Walk the file from the top and bump each logStage number by one.

- [ ] **Step 5: Run the new tests; expect PASS**

```
go test ./cmd/safe-init/... -run "TestOpenSecretListenerBindsSynchronously|TestAcceptAndReadSecretPerformsHandshake|TestReadSecretFromTCPWritesReadyBeforeRead" -v
```

Expected: all three PASS.

- [ ] **Step 6: Run full test + lint**

```
make test lint
```

Expected: green. If lint complains about the renumbered logStage calls being magic numbers, leave them — they match the existing pattern in the file.

- [ ] **Step 7: Commit**

```
git add cmd/safe-init/main.go cmd/safe-init/main_test.go
git commit -m "fix: open safe-init bootstrap listener before loading config"
```

---

## Task 3: Host-side `PipeKey` reads READY, retries dial on failure

**Files:**
- Modify: `internal/dockerrun/keypipe.go:23-82` — `PipeKey` dial-write loop becomes dial-handshake-write-retry
- Modify: `internal/dockerrun/keypipe_test.go:30-60` — `TestRawTCPSecretDelivery` server now writes READY before reading
- Modify: `internal/dockerrun/keypipe_test.go` — add a test for the retry-on-no-READY case

This is the host counterpart to Task 1+2. The handshake's whole point is to make the host re-dial when the connection was accepted but not actually forwarded to the container (the vpnkit silent-drop case). Without the host change, Task 1+2 are useless: the container would write READY into a one-shot connection that the host doesn't read before writing the secret.

- [ ] **Step 1: Write a failing test for retry-on-no-READY**

Append to `internal/dockerrun/keypipe_test.go`:

```go
import (
	"sync/atomic"
)

// TestPipeKeyReadsReadyAndRetries simulates the macOS Docker Desktop
// vpnkit case: the FIRST dial succeeds (vpnkit accepts) but the
// server closes the connection without sending READY (vpnkit couldn't
// forward to the container). PipeKey must NOT write the secret to
// that connection; it must re-dial. The SECOND dial gets a real
// server that sends READY and reads the secret correctly.
func TestPipeKeyReadsReadyAndRetries(t *testing.T) {
	t.Skip("PipeKey's discovery loop shells out to `docker port`; covered by a lower-level test below")
}

// TestRawTCPHandshakeAndSecretDelivery is the wire-format test for
// the handshake variant of pipekey (parallel to TestRawTCPSecretDelivery).
// Server writes SAFE-INIT-READY\n; client reads it; client writes secret.
func TestRawTCPHandshakeAndSecretDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	gotCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			gotCh <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		_, werr := conn.Write([]byte("SAFE-INIT-READY\n"))
		if werr != nil {
			gotCh <- ""
			return
		}
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		gotCh <- string(buf[:n])
	}()

	addr := ln.Addr().String()
	got, err := dockerrun.DialWriteSecret(context.Background(), addr, "secret-bytes", 2*time.Second)
	require.NoError(t, err)
	require.True(t, got, "DialWriteSecret should report success")

	select {
	case s := <-gotCh:
		require.Equal(t, "secret-bytes\n", s)
	case <-time.After(2 * time.Second):
		t.Fatal("server never received secret")
	}
}

// TestDialWriteSecretRetriesWhenServerClosesBeforeReady simulates the
// vpnkit-accept-then-close case explicitly: a goroutine accepts and
// immediately closes (without writing READY) for the first N attempts,
// then switches to the well-behaved protocol for the (N+1)th.
func TestDialWriteSecretRetriesWhenServerClosesBeforeReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	var attempts atomic.Int32
	gotCh := make(chan string, 1)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			n := attempts.Add(1)
			if n <= 2 {
				// First two: vpnkit-style accept-then-close.
				_ = conn.Close()
				continue
			}
			// Third: well-behaved.
			_, _ = conn.Write([]byte("SAFE-INIT-READY\n"))
			buf := make([]byte, 1024)
			rn, _ := conn.Read(buf)
			gotCh <- string(buf[:rn])
			_ = conn.Close()
			return
		}
	}()

	addr := ln.Addr().String()
	ok, err := dockerrun.DialWriteSecret(context.Background(), addr, "secret-bytes", 3*time.Second)
	require.NoError(t, err)
	require.True(t, ok)

	select {
	case s := <-gotCh:
		require.Equal(t, "secret-bytes\n", s)
	case <-time.After(2 * time.Second):
		t.Fatal("server never received secret on third attempt")
	}
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}
```

Also REPLACE the existing `TestRawTCPSecretDelivery` (lines 30-60) with a version that matches the new wire format — server writes READY before reading:

```go
// TestRawTCPSecretDelivery locks in the wire format the in-container
// reader expects: server writes "SAFE-INIT-READY\n" on accept, then
// reads <secret>\n. This isn't a test of PipeKey itself; it just
// pins the protocol.
func TestRawTCPSecretDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	gotCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			gotCh <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		if _, werr := conn.Write([]byte("SAFE-INIT-READY\n")); werr != nil {
			gotCh <- ""
			return
		}
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		gotCh <- string(buf[:n])
	}()

	addr := ln.Addr().String()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	// Read READY first (matches the host's PipeKey behaviour).
	buf := make([]byte, len("SAFE-INIT-READY\n"))
	_, err = conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "SAFE-INIT-READY\n", string(buf))
	_, err = conn.Write([]byte("secret-bytes\n"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	select {
	case got := <-gotCh:
		require.Equal(t, "secret-bytes\n", got)
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not deliver bytes")
	}
}
```

- [ ] **Step 2: Run; expect FAIL (undefined: dockerrun.DialWriteSecret)**

```
go test ./internal/dockerrun/... -run "TestRawTCPHandshakeAndSecretDelivery|TestDialWriteSecretRetriesWhenServerClosesBeforeReady|TestRawTCPSecretDelivery" -v
```

Expected: FAIL — compile error, `DialWriteSecret` undefined.

- [ ] **Step 3: Implement `DialWriteSecret` and refactor `PipeKey` to use it**

In `internal/dockerrun/keypipe.go`, ADD the `safeInitReadyLine` constant and the `DialWriteSecret` function above `PipeKey`:

```go
// safeInitReadyLine is the in-container listener's one-way handshake
// byte. Mirror of cmd/safe-init/main.go:safeInitReadyLine; the two
// must stay in lockstep. The host reads this before writing the
// secret so it can re-dial if vpnkit / docker-proxy accepted on the
// host side but failed to forward to the container.
const safeInitReadyLine = "SAFE-INIT-READY\n"

// DialWriteSecret dials addr, performs the SAFE-INIT-READY handshake
// (read READY before writing), and writes secret+"\n". If the
// handshake fails (timeout / EOF / wrong bytes), it closes the
// connection and re-dials until ctx is done or the per-call deadline
// expires. The boolean return is true on success.
//
// This function is exported separately from PipeKey so it can be unit
// tested without spinning up a docker container.
func DialWriteSecret(ctx context.Context, addr, secret string, deadline time.Duration) (bool, error) {
	overall := time.Now().Add(deadline)
	d := net.Dialer{}
	want := []byte(safeInitReadyLine)
	attempts := 0
	for time.Now().Before(overall) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		attempts++
		conn, derr := d.DialContext(ctx, "tcp", addr)
		if derr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Read READY with a tight timeout. If the server is the real
		// in-container listener, READY arrives in single-digit ms.
		// If vpnkit accepted-but-couldn't-forward, the read will EOF
		// or time out, and we'll retry.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(want))
		if _, rerr := io.ReadFull(conn, buf); rerr != nil {
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !bytes.Equal(buf, want) {
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Handshake good — write the secret.
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, werr := conn.Write([]byte(secret + "\n")); werr != nil {
			_ = conn.Close()
			return false, fmt.Errorf("write secret: %w", werr)
		}
		_ = conn.Close()
		return true, nil
	}
	return false, fmt.Errorf("dial %s: no successful READY handshake after %d attempts", addr, attempts)
}
```

Add the `bytes` and `io` imports at the top of `keypipe.go`:

```go
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)
```

REPLACE the dial-and-write portion of `PipeKey` (the loop starting `var conn net.Conn` through `log("write OK; returning")`, roughly lines 42-80) with a single call to `DialWriteSecret`:

```go
	log("starting dial + handshake")
	deadlineRemaining := time.Until(deadline)
	if deadlineRemaining < time.Second {
		deadlineRemaining = time.Second
	}
	ok, err := DialWriteSecret(ctx, hostAddr, secret, deadlineRemaining)
	if err != nil {
		log("dial+handshake failed: " + err.Error())
		return fmt.Errorf("dial %s: %w", hostAddr, err)
	}
	if !ok {
		return fmt.Errorf("dial %s: handshake never completed", hostAddr)
	}
	log("handshake OK + secret written")
	return nil
}
```

(The full new body of `PipeKey` after these edits is: log start → discoverHostPort → DialWriteSecret. Keep the existing `log` closure and the `deadline` computation.)

- [ ] **Step 4: Run the three tests; expect PASS**

```
go test ./internal/dockerrun/... -run "TestRawTCPHandshakeAndSecretDelivery|TestDialWriteSecretRetriesWhenServerClosesBeforeReady|TestRawTCPSecretDelivery" -v
```

Expected: all PASS. The retry test in particular should show `attempts >= 3` (first two are vpnkit-accept-close, third is the real one).

- [ ] **Step 5: Run full test + lint**

```
make test lint
```

Expected: green. If `TestPipeKeyTimesOutOnUnknownContainer` (existing test) regresses, it shouldn't — that test exercises `discoverHostPort` which we didn't touch.

- [ ] **Step 6: Commit**

```
git add internal/dockerrun/keypipe.go internal/dockerrun/keypipe_test.go
git commit -m "fix: pipekey reads SAFE-INIT-READY and retries on handshake failure"
```

---

## Task 4: Pass terminal-identification env vars through to enable shift+enter

**Files:**
- Create: `internal/dockerrun/envdefaults.go` — the always-on terminal var list
- Modify: `internal/dockerrun/builder.go:181-183` — augment user's `EnvPassthrough` with the defaults
- Modify: `internal/dockerrun/builder_test.go` — assert the new `-e` flags appear
- Modify: `cmd/safe/init.go:137` — update the template comment so new users see what's auto-included
- Modify: `docs/CONFIG.md:49,73` — document the auto-included terminal vars

Claude code reads `TERM_PROGRAM` / `TERM_PROGRAM_VERSION` / `COLORTERM` to decide whether to enable the kitty keyboard protocol (which is what makes shift+enter distinguishable from enter). The default `env_passthrough` in safe.yaml is `[TERM, LANG, TZ]` — missing those. Add them as a built-in always-on list rather than just changing the template so existing user configs pick up the fix without a re-`safe init`.

- [ ] **Step 1: Write the failing test**

Append to `internal/dockerrun/builder_test.go`:

```go
func TestBuildArgvIncludesTerminalEnvDefaultsEvenWhenConfigOmitsThem(t *testing.T) {
	cfg := minimalConfig()
	cfg.EnvPassthrough = []string{"LANG"} // user did NOT list TERM_PROGRAM etc.
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	joined := strings.Join(argv, " ")
	for _, k := range []string{"TERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "COLORTERM"} {
		require.Contains(t, joined, "-e "+k, "%s must be auto-passthroughed so claude can enable kitty keyboard protocol (shift+enter)", k)
	}
	// User's explicit entry must still appear.
	require.Contains(t, joined, "-e LANG")
}

// TestBuildArgvDoesNotDuplicateTerminalEnvDefaults verifies the merge
// is idempotent: if the user's config already lists TERM, we don't
// emit -e TERM twice.
func TestBuildArgvDoesNotDuplicateTerminalEnvDefaults(t *testing.T) {
	cfg := minimalConfig()
	cfg.EnvPassthrough = []string{"TERM", "LANG"}
	argv, err := dockerrun.BuildArgv(dockerrun.Inputs{
		Config:    cfg,
		AgentName: "claude",
		CWD:       "/p",
		RunID:     "x",
		ConfigDir: "/tmp/safe-cfg-x",
	})
	require.NoError(t, err)
	count := 0
	for i := range argv {
		if argv[i] == "TERM" && i > 0 && argv[i-1] == "-e" {
			count++
		}
	}
	require.Equal(t, 1, count, "TERM should be emitted once, not duplicated")
}
```

- [ ] **Step 2: Run; expect FAIL**

```
go test ./internal/dockerrun/... -run "TestBuildArgvIncludesTerminalEnvDefaultsEvenWhenConfigOmitsThem|TestBuildArgvDoesNotDuplicateTerminalEnvDefaults" -v
```

Expected: FAIL — the current builder only emits what's in `cfg.EnvPassthrough`.

- [ ] **Step 3: Create the defaults file**

Create `internal/dockerrun/envdefaults.go`:

```go
package dockerrun

// TerminalEnvPassthroughDefaults are env vars that SAFE always passes
// through from the host into the container, on top of whatever the
// user listed in safe.yaml's env_passthrough.
//
// These exist because claude code (and other TUI agents) reads them
// to decide which terminal features to enable — most importantly the
// kitty keyboard protocol, which is what makes shift+enter
// distinguishable from enter. Without TERM_PROGRAM set, claude falls
// back to a generic xterm assumption and shift+enter becomes a no-op.
//
// None of these vars carry secrets; they identify the host terminal
// emulator. They're hardcoded rather than added to env_passthrough's
// YAML default so existing user configs pick up the fix without
// requiring a safe.yaml edit.
var TerminalEnvPassthroughDefaults = []string{
	"TERM",
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"COLORTERM",
}

// mergeEnvPassthrough returns the union of user's list and the
// terminal defaults, preserving user order first and skipping
// duplicates (case-sensitive — env var names are case-sensitive).
func mergeEnvPassthrough(user []string) []string {
	seen := make(map[string]struct{}, len(user)+len(TerminalEnvPassthroughDefaults))
	out := make([]string, 0, len(user)+len(TerminalEnvPassthroughDefaults))
	for _, k := range user {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for _, k := range TerminalEnvPassthroughDefaults {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 4: Wire it into `BuildArgv`**

In `internal/dockerrun/builder.go`, REPLACE lines 181-183 (the existing `for _, k := range in.Config.EnvPassthrough { ... }` block) with:

```go
	for _, k := range mergeEnvPassthrough(in.Config.EnvPassthrough) {
		argv = append(argv, "-e", k)
	}
```

- [ ] **Step 5: Run the new tests; expect PASS**

```
go test ./internal/dockerrun/... -run "TestBuildArgvIncludesTerminalEnvDefaultsEvenWhenConfigOmitsThem|TestBuildArgvDoesNotDuplicateTerminalEnvDefaults" -v
```

Expected: both PASS.

- [ ] **Step 6: Update the existing `TestBuildArgvOnlyAllowedEnvPassthrough` test if it asserts an exact env var set**

Read `internal/dockerrun/builder_test.go` around line 100. If `TestBuildArgvOnlyAllowedEnvPassthrough` asserts that ONLY `TERM` and `LANG` are emitted, update it to allow the new defaults to also appear (or rename the test to reflect the new semantics). If it just asserts that `TERM` and `LANG` are present without exclusion, no change needed.

- [ ] **Step 7: Update the safe.yaml template**

In `cmd/safe/init.go`, find the line:

```
env_passthrough: [TERM, LANG, TZ]
```

REPLACE with:

```
# env_passthrough: env vars copied from host into the container.
# TERM, TERM_PROGRAM, TERM_PROGRAM_VERSION, COLORTERM are ALWAYS
# passed through (required for shift+enter and color detection in
# TUI agents); the list below is appended to those defaults.
env_passthrough: [LANG, TZ]
```

- [ ] **Step 8: Update `docs/CONFIG.md`**

In `docs/CONFIG.md`, find the two existing references to `[TERM, LANG, TZ]` (around lines 49 and 73). REPLACE both with text that names the auto-included defaults and shows the new template default. Concretely:

- The example block (~line 49): change `env_passthrough: [TERM, LANG, TZ]` to `env_passthrough: [LANG, TZ]` and add a one-line preamble: `# TERM*, COLORTERM are always passed through (built-in default).`
- The table row (~line 73): change the default column from `[TERM, LANG, TZ]` to `[LANG, TZ]` and add a "Notes" sentence: `Always-on defaults TERM, TERM_PROGRAM, TERM_PROGRAM_VERSION, COLORTERM are appended automatically.`

- [ ] **Step 9: Run full test + lint**

```
make test lint
```

Expected: green.

- [ ] **Step 10: Commit**

```
git add internal/dockerrun/envdefaults.go internal/dockerrun/builder.go internal/dockerrun/builder_test.go cmd/safe/init.go docs/CONFIG.md
git commit -m "feat: always pass TERM_PROGRAM/COLORTERM through so shift+enter works"
```

---

## Task 5: Rebuild the image and manually verify on macOS Docker Desktop

This is the only step that needs the user's hands because the bugs are environmental (Docker Desktop vpnkit, terminal emulator).

- [ ] **Step 1: Rebuild the container image**

```
make build
docker-buildx build -t safe-runtime:dev .
```

Expected: both succeed.

- [ ] **Step 2: Run `safe claude` 20 times in a row, watch for timeouts**

```
for i in $(seq 1 20); do
  echo "=== run $i ==="
  echo /quit | safe claude 2>&1 | grep -E "(safe-init|pipekey)" | tail -5
done
```

Expected: zero `accept on :9099: i/o timeout` errors. On macOS you may see `pipekey: handshake retry attempt=N` log lines on a fraction of runs — that's the fix working; the user-facing error is gone.

- [ ] **Step 3: Verify shift+enter inserts a newline**

```
safe claude
```

Inside the REPL, type some text, press shift+enter, type more text, then enter. Confirm the prompt contained both lines (claude submits a multi-line message). Compare with bare `claude` outside the sandbox — behavior should match.

- [ ] **Step 4: If anything regressed, do NOT amend the previous commits**

Open a new task in this plan describing the failure and propose a fix.

---

## Self-review notes

- **Spec coverage:** Bug 1 (vpnkit race) → Tasks 1+2+3. Bug 2 (shift+enter) → Task 4. Task 5 = manual verification. Every requirement traced.
- **Placeholder scan:** No TBDs, no "add appropriate error handling" — all code is concrete.
- **Type consistency:** `safeInitReadyLine` constant exists in BOTH `cmd/safe-init/main.go` (Task 1) and `internal/dockerrun/keypipe.go` (Task 3). The constant body is identical (`"SAFE-INIT-READY\n"`). The comment in `keypipe.go` calls out the mirror requirement; if you change one, change the other.
- **TDD discipline:** Every Task starts with a failing test. The handshake test in Task 1 fails the existing code; the retry test in Task 3 fails because `DialWriteSecret` doesn't exist; the env-defaults test in Task 4 fails because the merge function doesn't exist.
- **One commit per task** per the project's `[[feedback-commit-cadence]]` rule (overrides the global "one commit at end").
