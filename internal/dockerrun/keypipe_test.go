package dockerrun_test

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/dockerrun"
	"github.com/stretchr/testify/require"
)

func TestPipeKeyWritesOneLineAndCloses(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "keyholder.sock")

	got := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			got <- "<accept failed: " + err.Error() + ">"
			return
		}
		defer conn.Close()
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
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "no-listener.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := dockerrun.PipeKey(ctx, socketPath, "sk-test")
	require.Error(t, err)
}
