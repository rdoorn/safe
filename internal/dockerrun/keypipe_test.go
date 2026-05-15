package dockerrun_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

// shortTempDir returns a short path under /tmp suitable for hosting a
// Unix domain socket on macOS (where t.TempDir paths exceed the 104-char
// sun_path limit).
func shortTempDir(_ string) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	p := filepath.Join("/tmp", "safe-test-"+hex.EncodeToString(b))
	if err := os.Mkdir(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

func TestPipeKeyWritesOneLineAndCloses(t *testing.T) {
	// Use a short path because UNIX socket paths are limited (~104 chars
	// on macOS, 108 on Linux). t.TempDir() under /var/folders/ on macOS
	// blows past that limit with even modest test names.
	dir, err := shortTempDir(t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "k.sock")

	got := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			got <- "<accept failed: " + err.Error() + ">"
			return
		}
		defer func() { _ = conn.Close() }()
		b, _ := io.ReadAll(conn)
		got <- string(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, dockerrun.PipeKey(ctx, socketPath, "sk-test"))

	wg.Wait()
	select {
	case s := <-got:
		require.Equal(t, "sk-test\n", s)
	case <-time.After(time.Second):
		t.Fatal("never received the key on the socket")
	}
}

func TestPipeKeyTimesOutIfNoListener(t *testing.T) {
	dir, err := shortTempDir(t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "no.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = dockerrun.PipeKey(ctx, socketPath, "sk-test")
	require.Error(t, err)
}
