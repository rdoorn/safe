package resolver_test

import (
	"testing"

	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

func TestMatcherExact(t *testing.T) {
	m := resolver.NewMatcher([]string{"api.anthropic.com"})
	require.True(t, m.Allows("api.anthropic.com"))
	require.False(t, m.Allows("evil.com"))
	require.False(t, m.Allows("api.anthropic.com.evil.com"))
}

func TestMatcherCaseInsensitive(t *testing.T) {
	m := resolver.NewMatcher([]string{"API.Anthropic.com"})
	require.True(t, m.Allows("api.anthropic.com"))
	require.True(t, m.Allows("API.ANTHROPIC.COM"))
}

func TestMatcherTrailingDot(t *testing.T) {
	// DNS queries often arrive fully-qualified with the root dot.
	m := resolver.NewMatcher([]string{"api.anthropic.com"})
	require.True(t, m.Allows("api.anthropic.com."))
}

func TestMatcherWildcardSuffix(t *testing.T) {
	m := resolver.NewMatcher([]string{"*.example.com"})
	require.True(t, m.Allows("foo.example.com"))
	require.True(t, m.Allows("a.b.example.com"))
	require.False(t, m.Allows("example.com"), "wildcard requires at least one label before suffix")
	require.False(t, m.Allows("notexample.com"))
}

func TestMatcherWildcardAndExact(t *testing.T) {
	m := resolver.NewMatcher([]string{"example.com", "*.example.com"})
	require.True(t, m.Allows("example.com"))
	require.True(t, m.Allows("api.example.com"))
}

func TestMatcherEmpty(t *testing.T) {
	m := resolver.NewMatcher(nil)
	require.False(t, m.Allows("anything.com"))
}

func TestMatcherStripsTrailingDot(t *testing.T) {
	m := resolver.NewMatcher([]string{"*.example.com."})
	require.True(t, m.Allows("foo.example.com"))
}
