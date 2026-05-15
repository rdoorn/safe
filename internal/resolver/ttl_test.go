package resolver_test

import (
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

func TestClampTTLInRange(t *testing.T) {
	got := resolver.ClampTTL(60*time.Second, 30*time.Second, time.Hour)
	require.Equal(t, 60*time.Second, got)
}

func TestClampTTLBelowMin(t *testing.T) {
	got := resolver.ClampTTL(1*time.Second, 30*time.Second, time.Hour)
	require.Equal(t, 30*time.Second, got)
}

func TestClampTTLAboveMax(t *testing.T) {
	got := resolver.ClampTTL(24*time.Hour, 30*time.Second, time.Hour)
	require.Equal(t, time.Hour, got)
}

func TestClampTTLZero(t *testing.T) {
	got := resolver.ClampTTL(0, 30*time.Second, time.Hour)
	require.Equal(t, 30*time.Second, got)
}

func TestClampTTLDefaults(t *testing.T) {
	require.Equal(t, 30*time.Second, resolver.DefaultMinTTL)
	require.Equal(t, time.Hour, resolver.DefaultMaxTTL)
}

func TestClampTTLFromSeconds(t *testing.T) {
	require.Equal(t, 30*time.Second, resolver.ClampTTLSeconds(5, 30*time.Second, time.Hour))
	require.Equal(t, time.Hour, resolver.ClampTTLSeconds(99999, 30*time.Second, time.Hour))
	require.Equal(t, 300*time.Second, resolver.ClampTTLSeconds(300, 30*time.Second, time.Hour))
}
