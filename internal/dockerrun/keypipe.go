package dockerrun

import (
	"context"
	"fmt"
	"net"
	"time"
)

// PipeKey waits for the in-container safe-init to listen on socketPath
// and writes the API key followed by a newline. The connection is then
// closed; safe-init reads one line on the other end. PipeKey honours ctx.
//
// The connection retry exists because safe-init binds the socket after
// /proc remount and safe-fw seed; on cold start that may take a couple
// hundred ms.
func PipeKey(ctx context.Context, socketPath, key string) error {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(5 * time.Second)
	}

	var conn net.Conn
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c, err := net.Dial("unix", socketPath)
		if err == nil {
			conn = c
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("deadline exceeded waiting for %s", socketPath)
		}
		return fmt.Errorf("connect %s: %w", socketPath, lastErr)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(key + "\n")); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
