package keyholder_test

import (
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/keyholder"
	"github.com/stretchr/testify/require"
)

func TestBootstrapReadsOneLine(t *testing.T) {
	r := strings.NewReader("sk-from-stdin\n")
	k, err := keyholder.Bootstrap(r)
	require.NoError(t, err)
	require.Equal(t, "Bearer sk-from-stdin", k.AuthHeaderValue("Bearer"))
}

func TestBootstrapTrimsWhitespace(t *testing.T) {
	r := strings.NewReader("  sk-padded  \n")
	k, err := keyholder.Bootstrap(r)
	require.NoError(t, err)
	require.Equal(t, "sk-padded", k.AuthHeaderValue(""))
}

func TestBootstrapRejectsEmpty(t *testing.T) {
	_, err := keyholder.Bootstrap(strings.NewReader(""))
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestBootstrapRejectsWhitespaceOnly(t *testing.T) {
	_, err := keyholder.Bootstrap(strings.NewReader("   \n"))
	require.Error(t, err)
}

func TestBootstrapIgnoresExtraLines(t *testing.T) {
	// Anything after the first newline is discarded so the key never
	// contains a stray secret-like blob.
	k, err := keyholder.Bootstrap(strings.NewReader("sk-one\nsk-two\nsk-three\n"))
	require.NoError(t, err)
	require.Equal(t, "sk-one", k.AuthHeaderValue(""))
}
