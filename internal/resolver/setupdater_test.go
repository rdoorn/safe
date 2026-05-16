package resolver_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

// On non-Linux platforms (CI runners on Linux exercise the netlink path
// end-to-end), SetUpdater's apply step returns "requires Linux". The
// tests here only cover the platform-agnostic surface: input validation
// and the empty-batch fast path.

func TestSetUpdaterEmptyBatchIsNoop(t *testing.T) {
	u := &resolver.SetUpdater{}
	require.NoError(t, u.AddMany(context.Background(), nil, time.Minute))
}

func TestSetUpdaterRejectsNilIP(t *testing.T) {
	u := &resolver.SetUpdater{}
	err := u.Add(context.Background(), nil, time.Minute)
	require.Error(t, err)
}

func TestSetUpdaterDefaultsApplied(t *testing.T) {
	// Calling Add will trigger applyDefaults internally. We assert the
	// defaults are filled in even when the kernel apply step returns an
	// "unsupported platform" error on macOS — meaning AddMany got past
	// validation and into the apply step.
	u := &resolver.SetUpdater{}
	err := u.Add(context.Background(), net.ParseIP("1.2.3.4"), time.Minute)
	// On Linux this hits real netlink; on macOS it returns the platform
	// stub error. Either way validation passed.
	if err != nil {
		require.NotContains(t, err.Error(), "nil IP", "validation should not flag this input")
	}
	require.Equal(t, "safe", u.TableName)
	require.Equal(t, "allowed_v4", u.SetNameV4)
	require.Equal(t, "allowed_v6", u.SetNameV6)
}
