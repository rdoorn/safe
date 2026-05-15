package initd_test

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/initd"
	"github.com/stretchr/testify/require"
)

// fakeSignaller captures what would have been sent to the child.
type fakeSignaller struct {
	mu      sync.Mutex
	signals []syscall.Signal
}

func (f *fakeSignaller) Signal(_ int, s syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, s)
	return nil
}

func (f *fakeSignaller) snapshot() []syscall.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]syscall.Signal, len(f.signals))
	copy(out, f.signals)
	return out
}

func TestSignalForwarderRelaysSIGTERM(t *testing.T) {
	fake := &fakeSignaller{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan initd.SignalEvent, 4)
	done := make(chan struct{})
	go func() {
		initd.ForwardSignals(ctx, in, 1234, fake)
		close(done)
	}()

	in <- initd.SignalEvent{Sig: syscall.SIGTERM}
	in <- initd.SignalEvent{Sig: syscall.SIGINT}

	// Give the forwarder a chance to drain the channel.
	require.Eventually(t, func() bool {
		return len(fake.snapshot()) == 2
	}, time.Second, 10*time.Millisecond)

	got := fake.snapshot()
	require.Equal(t, syscall.SIGTERM, got[0])
	require.Equal(t, syscall.SIGINT, got[1])

	cancel()
	<-done
}

func TestSignalForwarderExitsOnContextDone(t *testing.T) {
	fake := &fakeSignaller{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		initd.ForwardSignals(ctx, make(chan initd.SignalEvent), 1, fake)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not exit when context was cancelled")
	}
}
