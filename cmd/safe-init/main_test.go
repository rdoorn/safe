package main

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestReadSecretFromTCPWritesReadyBeforeRead verifies that readSecretFromTCP
// writes safeInitReadyLine to the accepted connection BEFORE it reads the
// secret. This is the host's signal that the in-container listener really
// accepted the connection (rather than vpnkit accepting on the host side and
// dropping bytes).
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

// TestOpenSecretListenerBindsSynchronously verifies openSecretListener binds
// the port WITHOUT blocking on accept, so callers can listen-then-load-config
// and only accept once they're ready.
func TestOpenSecretListenerBindsSynchronously(t *testing.T) {
	ln, err := openSecretListener("0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().String()
	require.NotEmpty(t, addr)
	require.Contains(t, addr, "[::]:")
}

// TestAcceptAndReadSecretPerformsHandshake verifies acceptAndReadSecret reads
// a secret from an externally-opened listener, performing the SAFE-INIT-READY
// handshake before the read.
func TestAcceptAndReadSecretPerformsHandshake(t *testing.T) {
	ln, err := openSecretListener("0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	parts := strings.Split(ln.Addr().String(), ":")
	port := parts[len(parts)-1]

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
