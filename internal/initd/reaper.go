// Package initd implements the SAFE in-container PID-1 (safe-init).
package initd

import (
	"context"
	"syscall"
)

// SignalEvent wraps the underlying signal so the forwarder doesn't need
// to import os.Signal directly in tests.
type SignalEvent struct {
	Sig syscall.Signal
}

// Signaller is anything that can deliver a Unix signal to a pid. The
// production implementation calls syscall.Kill; tests substitute a fake.
type Signaller interface {
	Signal(pid int, sig syscall.Signal) error
}

// KillSignaller is the production Signaller backed by syscall.Kill.
type KillSignaller struct{}

// Signal sends sig to pid.
func (KillSignaller) Signal(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// ForwardSignals reads signal events from in and forwards them to childPID
// via sig. It returns when ctx is cancelled or in is closed.
//
// safe-init wires the host signal channel (os/signal.Notify) into this
// function so SIGTERM/SIGINT delivered to PID 1 reach the agent. This
// is the standard "init forwarder" pattern; the kernel does not propagate
// signals across the PID-1 boundary on its own.
func ForwardSignals(ctx context.Context, in <-chan SignalEvent, childPID int, sig Signaller) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			_ = sig.Signal(childPID, ev.Sig)
		}
	}
}
