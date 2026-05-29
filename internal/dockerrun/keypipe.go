// Package dockerrun helpers; this file owns the host-side keyholder
// secret bootstrap.
package dockerrun

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
		// in-container listener, READY arrives in single-digit ms. If
		// vpnkit accepted-but-couldn't-forward, the read will EOF or
		// time out, and we'll retry.
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

// PipeKey discovers the ephemeral host port docker mapped to the
// container's BootstrapPort, connects to 127.0.0.1:<port>, and writes
// `secret + "\n"`. Discovery polls `docker port <containerName>
// <BootstrapPort>/tcp` until the mapping is reported (docker only
// reports a mapping once the container is up).
//
// The connect retry loop tolerates a brief window where docker has
// printed the mapping but the in-container listener isn't quite ready.
func PipeKey(ctx context.Context, containerName, secret string) error {
	log := func(msg string) {
		// \r\n because by the time this runs, docker has put the host
		// terminal into raw mode so \n alone wouldn't carriage-return.
		_, _ = fmt.Fprintf(os.Stderr, "pipekey: %s\r\n", msg)
	}
	log("start container=" + containerName)
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(10 * time.Second)
	}

	hostAddr, err := discoverHostPort(ctx, containerName, deadline)
	if err != nil {
		log("discoverHostPort error: " + err.Error())
		return err
	}
	log("discovered hostAddr=" + hostAddr)

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

func discoverHostPort(ctx context.Context, containerName string, deadline time.Time) (string, error) {
	tries := 0
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		tries++
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, BootstrapPort+"/tcp").Output()
		if err == nil {
			addr := strings.TrimSpace(string(out))
			if addr != "" {
				_, _ = fmt.Fprintf(os.Stderr, "pipekey: docker port returned after %d tries: %q\r\n", tries, addr)
				// `docker port` returns "127.0.0.1:54321" (possibly multiple lines for v4/v6).
				return strings.SplitN(addr, "\n", 2)[0], nil
			}
		} else if tries == 1 || tries%20 == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "pipekey: docker port try %d err=%v\r\n", tries, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port %s %s/tcp did not return a host mapping before deadline (%d tries)", containerName, BootstrapPort, tries)
}
