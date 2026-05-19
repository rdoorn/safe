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
// `secret + "\n"`. Discovery polls `docker port <containerName>
// <BootstrapPort>/tcp` until the mapping is reported (docker only
// reports a mapping once the container is up).
//
// The connect retry loop tolerates a brief window where docker has
// printed the mapping but the in-container listener isn't quite ready.
func PipeKey(ctx context.Context, containerName, secret string) error {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(10 * time.Second)
	}

	hostAddr, err := discoverHostPort(ctx, containerName, deadline)
	if err != nil {
		return err
	}

	var conn net.Conn
	var lastErr error
	d := net.Dialer{}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c, err := d.DialContext(ctx, "tcp", hostAddr)
		if err == nil {
			conn = c
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("deadline exceeded waiting for %s", hostAddr)
		}
		return fmt.Errorf("dial %s: %w", hostAddr, lastErr)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(secret + "\n")); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

func discoverHostPort(ctx context.Context, containerName string, deadline time.Time) (string, error) {
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, BootstrapPort+"/tcp").Output()
		if err == nil {
			addr := strings.TrimSpace(string(out))
			if addr != "" {
				// `docker port` returns "127.0.0.1:54321" (possibly multiple lines for v4/v6).
				return strings.SplitN(addr, "\n", 2)[0], nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port %s %s/tcp did not return a host mapping before deadline", containerName, BootstrapPort)
}
