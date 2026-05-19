package dockerrun_test

import (
	"context"
	"net"
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

// TestRawTCPSecretDelivery is a lower-level sanity check on the wire
// format: a goroutine accepts on a local listener; we manually dial it
// and write `<secret>\n`; the receiver reads it back. This isn't a test
// of PipeKey itself (we don't go through `docker port`) but it locks in
// the wire format the in-container reader expects.
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
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		gotCh <- string(buf[:n])
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
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
