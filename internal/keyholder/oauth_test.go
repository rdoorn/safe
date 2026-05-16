package keyholder_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/keyholder"
	"github.com/stretchr/testify/require"
)

// exampleCredentialsJSON is a fixture, not a real secret.
//
//nolint:gosec // fixture
const exampleCredentialsJSON = `{
  "claudeAiOauth": {
    "accessToken": "access-1",
    "refreshToken": "refresh-1",
    "expiresAt": 9999999999999,
    "scopes": ["user:profile", "user:inference"],
    "subscriptionType": "pro",
    "rateLimitTier": "free"
  }
}`

func TestParseOAuthCredentialsHappyPath(t *testing.T) {
	c, err := keyholder.ParseOAuthCredentials([]byte(exampleCredentialsJSON))
	require.NoError(t, err)
	require.Equal(t, "access-1", c.AccessToken)
	require.Equal(t, "refresh-1", c.RefreshToken)
	require.True(t, c.ExpiresAt.After(time.Now()))
}

func TestParseOAuthCredentialsMissingFields(t *testing.T) {
	cases := map[string]string{
		"empty json":          `{}`,
		"no oauth section":    `{"something":"else"}`,
		"missing accessToken": `{"claudeAiOauth":{"refreshToken":"r","expiresAt":1}}`,
		"missing refresh":     `{"claudeAiOauth":{"accessToken":"a","expiresAt":1}}`,
		"missing expiry":      `{"claudeAiOauth":{"accessToken":"a","refreshToken":"r"}}`,
	}
	for name, body := range cases {
		_, err := keyholder.ParseOAuthCredentials([]byte(body))
		require.Error(t, err, "expected error for %s", name)
	}
}

func TestOAuthTokenSourceUsesAccessToken(t *testing.T) {
	creds, err := keyholder.ParseOAuthCredentials([]byte(exampleCredentialsJSON))
	require.NoError(t, err)

	ts := keyholder.NewOAuthTokenSource(creds, "https://example.invalid/token", nil)
	require.Equal(t, "Bearer access-1", ts.AuthHeaderValue(""))
}

func TestOAuthTokenSourceRefreshesNearExpiry(t *testing.T) {
	// Token expires in 30 seconds — well inside our 2-minute skew —
	// so any call to AuthHeaderValue triggers a refresh attempt.
	creds := &keyholder.OAuthCredentials{
		AccessToken:  "old-access",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(30 * time.Second),
	}

	var refreshCalled int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalled++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "refresh-2",
			"expires_in":    900,
		})
	}))
	t.Cleanup(srv.Close)

	ts := keyholder.NewOAuthTokenSource(creds, srv.URL, srv.Client())
	require.Equal(t, "Bearer new-access", ts.AuthHeaderValue(""))
	require.Equal(t, 1, refreshCalled)

	// A second call when expiry is far in the future should NOT trigger
	// another refresh.
	require.Equal(t, "Bearer new-access", ts.AuthHeaderValue(""))
	require.Equal(t, 1, refreshCalled, "no extra refresh once token is fresh")
}

func TestOAuthTokenSourceForceRefresh(t *testing.T) {
	creds := &keyholder.OAuthCredentials{
		AccessToken:  "stale",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(time.Hour), // far future, normal call wouldn't refresh
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "post-force",
			"expires_in":   900,
		})
	}))
	t.Cleanup(srv.Close)

	ts := keyholder.NewOAuthTokenSource(creds, srv.URL, srv.Client())
	require.Equal(t, "Bearer stale", ts.AuthHeaderValue(""), "not yet refreshed")
	require.NoError(t, ts.ForceRefresh(context.Background()))
	require.Equal(t, "Bearer post-force", ts.AuthHeaderValue(""))
}

func TestOAuthTokenSourceRefreshErrorReturnsOldToken(t *testing.T) {
	creds := &keyholder.OAuthCredentials{
		AccessToken:  "old",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(10 * time.Second), // inside skew
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ts := keyholder.NewOAuthTokenSource(creds, srv.URL, srv.Client())
	// Should not panic; returns the stale token after refresh fails.
	require.Equal(t, "Bearer old", ts.AuthHeaderValue(""))
}

func TestOAuthTokenSourceStringRedacts(t *testing.T) {
	creds, _ := keyholder.ParseOAuthCredentials([]byte(exampleCredentialsJSON))
	ts := keyholder.NewOAuthTokenSource(creds, "", nil)
	require.NotContains(t, ts.String(), "access-1")
	require.NotContains(t, ts.String(), "refresh-1")
}
