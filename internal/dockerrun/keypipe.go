// Package dockerrun helpers; this file owns the host-side keyholder
// secret bootstrap.
package dockerrun

import (
	"context"
	"fmt"
	"net"
	"os"
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
	log := func(msg string) {
		_, _ = fmt.Fprintf(os.Stderr, "pipekey: %s\n", msg)
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

	var conn net.Conn
	var lastErr error
	attempts := 0
	d := net.Dialer{}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			log("ctx done during dial: " + ctx.Err().Error())
			return ctx.Err()
		default:
		}
		c, err := d.DialContext(ctx, "tcp", hostAddr)
		if err == nil {
			conn = c
			log(fmt.Sprintf("connected after %d attempts", attempts+1))
			break
		}
		lastErr = err
		attempts++
		if attempts == 1 || attempts%20 == 0 {
			log(fmt.Sprintf("dial attempt %d error: %s", attempts, err.Error()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("deadline exceeded waiting for %s", hostAddr)
		}
		log("never connected; lastErr=" + lastErr.Error())
		return fmt.Errorf("dial %s: %w", hostAddr, lastErr)
	}
	defer func() { _ = conn.Close() }()

	log(fmt.Sprintf("writing %d secret bytes", len(secret)+1))
	if _, err := conn.Write([]byte(secret + "\n")); err != nil {
		log("write error: " + err.Error())
		return fmt.Errorf("write secret: %w", err)
	}
	log("write OK; returning")
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
				_, _ = fmt.Fprintf(os.Stderr, "pipekey: docker port returned after %d tries: %q\n", tries, addr)
				// `docker port` returns "127.0.0.1:54321" (possibly multiple lines for v4/v6).
				return strings.SplitN(addr, "\n", 2)[0], nil
			}
		} else if tries == 1 || tries%20 == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "pipekey: docker port try %d err=%v\n", tries, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port %s %s/tcp did not return a host mapping before deadline (%d tries)", containerName, BootstrapPort, tries)
}
