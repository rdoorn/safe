package dockerrun_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

// TestPipeKeyTimesOutOnUnknownContainer exercises the discovery loop's
// timeout path: `docker port` exits non-zero immediately for an unknown
// container, but PipeKey should keep retrying within its deadline and
// return a wrapped error when the deadline expires.
func TestPipeKeyTimesOutOnUnknownContainer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	err := dockerrun.PipeKey(ctx, "safe-nonexistent-container-for-test", "secret")
	require.Error(t, err)
}

// TestRawTCPSecretDelivery locks in the wire format the in-container
// reader expects: server writes "SAFE-INIT-READY\n" on accept, then
// reads <secret>\n. This isn't a test of PipeKey itself; it just pins
// the protocol.
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

// TestRawTCPHandshakeAndSecretDelivery is the wire-format test for the
// handshake variant of pipekey: server writes SAFE-INIT-READY\n; client
// (DialWriteSecret) reads it; client writes secret.
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
		if _, werr := conn.Write([]byte("SAFE-INIT-READY\n")); werr != nil {
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
// immediately closes (without writing READY) for the first two attempts,
// then switches to the well-behaved protocol for the third.
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
