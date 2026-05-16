package keyholder_test

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rdoorn/safe/internal/keyholder"
	"github.com/stretchr/testify/require"
)

func TestRewriteBearerHeader(t *testing.T) {
	target, _ := url.Parse("https://api.anthropic.com")
	rw := &keyholder.Rewriter{
		Token:      keyholder.NewKey("sk-secret"),
		AuthHeader: "Authorization",
		AuthScheme: "Bearer",
		Target:     target,
	}

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer dummy")
	req.Host = "127.0.0.1:8443"

	rw.Apply(req)

	require.Equal(t, "Bearer sk-secret", req.Header.Get("Authorization"))
	require.Equal(t, "api.anthropic.com", req.Host)
	require.Equal(t, "api.anthropic.com", req.URL.Host)
	require.Equal(t, "https", req.URL.Scheme)
}

func TestRewriteAPIKeyHeader(t *testing.T) {
	target, _ := url.Parse("https://api.example.com")
	rw := &keyholder.Rewriter{
		Token:      keyholder.NewKey("sk-secret"),
		AuthHeader: "x-api-key",
		AuthScheme: "",
		Target:     target,
	}

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("x-api-key", "dummy")
	rw.Apply(req)

	require.Equal(t, "sk-secret", req.Header.Get("x-api-key"))
}

func TestRewriteStripsConflictingHeaders(t *testing.T) {
	target, _ := url.Parse("https://api.example.com")
	rw := &keyholder.Rewriter{
		Token:      keyholder.NewKey("sk-real"),
		AuthHeader: "Authorization",
		AuthScheme: "Bearer",
		Target:     target,
	}

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	// Agent shouldn't carry these but we strip just in case to avoid
	// leaking a dummy key into the upstream's logs as a "spare".
	req.Header.Set("Authorization", "Bearer dummy")
	req.Header.Set("x-api-key", "shouldnt-be-here")
	rw.Apply(req)

	require.Equal(t, "Bearer sk-real", req.Header.Get("Authorization"))
	require.Empty(t, req.Header.Get("x-api-key"))
}

func TestKeyAuthorizationFormat(t *testing.T) {
	k := keyholder.NewKey("sk-test")
	require.Equal(t, "Bearer sk-test", k.AuthHeaderValue("Bearer"))
	require.Equal(t, "sk-test", k.AuthHeaderValue(""))
}

func TestKeyDoesNotLeakViaFormat(t *testing.T) {
	k := keyholder.NewKey("sk-very-secret")
	// %v and %s on the Key value must not reveal the secret.
	require.Equal(t, "[REDACTED]", k.String())
	// Direct printf %v would also call String() via the Stringer interface.
}
