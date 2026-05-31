package keyholder

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRefresher is a TokenSource that also implements ForceRefresher. It
// returns "Bearer t0" until ForceRefresh is called, then "Bearer t1".
type fakeRefresher struct {
	mu         sync.Mutex
	val        string
	refreshes  int
	refreshErr error
}

func (f *fakeRefresher) AuthHeaderValue(_ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.val
}

func (f *fakeRefresher) String() string { return "[fake]" }

func (f *fakeRefresher) ForceRefresh(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	if f.refreshErr != nil {
		return f.refreshErr
	}
	f.val = "Bearer t1"
	return nil
}

func newTestRequest(t *testing.T, url, body string, authHeader, authValue string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set(authHeader, authValue)
	return req
}

func TestRefreshingTransportRetriesOn401(t *testing.T) {
	var (
		mu       sync.Mutex
		seenAuth []string
		seenBody []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
		seenBody = append(seenBody, string(b))
		n := len(seenAuth)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	tok := &fakeRefresher{val: "Bearer t0"}
	rt := &refreshingTransport{
		base:       http.DefaultTransport,
		token:      tok,
		authHeader: "Authorization",
		authScheme: "Bearer",
	}

	req := newTestRequest(t, srv.URL, "payload", "Authorization", tok.AuthHeaderValue("Bearer"))
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 1, tok.refreshes, "ForceRefresh should fire exactly once")
	require.Equal(t, []string{"Bearer t0", "Bearer t1"}, seenAuth, "retry must carry the refreshed header")
	require.Equal(t, []string{"payload", "payload"}, seenBody, "body must be replayed on retry")
}

func TestRefreshingTransportPassesThrough401WhenRefreshFails(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tok := &fakeRefresher{val: "Bearer t0", refreshErr: context.DeadlineExceeded}
	rt := &refreshingTransport{base: http.DefaultTransport, token: tok, authHeader: "Authorization", authScheme: "Bearer"}

	req := newTestRequest(t, srv.URL, "payload", "Authorization", tok.AuthHeaderValue("Bearer"))
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "original 401 should be returned")
	require.Equal(t, 1, tok.refreshes, "one refresh attempt")
	require.Equal(t, 1, hits, "no replay when refresh fails")
}

func TestRefreshingTransportNoRetryOnSuccess(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tok := &fakeRefresher{val: "Bearer t0"}
	rt := &refreshingTransport{base: http.DefaultTransport, token: tok, authHeader: "Authorization", authScheme: "Bearer"}

	req := newTestRequest(t, srv.URL, "payload", "Authorization", tok.AuthHeaderValue("Bearer"))
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 0, tok.refreshes, "no refresh on a successful first attempt")
	require.Equal(t, 1, hits)
}

func TestNewProxyWrapsTransportOnlyForRefreshableToken(t *testing.T) {
	target, err := url.Parse("https://example.invalid")
	require.NoError(t, err)

	// OAuth-style token (ForceRefresher) → wrapped.
	oauthProxy := NewProxy(ProxyConfig{Token: &fakeRefresher{val: "Bearer t0"}, AuthHeader: "Authorization", AuthScheme: "Bearer", Target: target})
	_, wrapped := oauthProxy.Transport.(*refreshingTransport)
	require.True(t, wrapped, "oauth token source should get the refreshing transport")

	// Static API key (no ForceRefresh) → not wrapped.
	keyProxy := NewProxy(ProxyConfig{Token: NewKey("sk-test"), AuthHeader: "x-api-key", AuthScheme: "", Target: target})
	_, wrappedKey := keyProxy.Transport.(*refreshingTransport)
	require.False(t, wrappedKey, "apikey mode must not be wrapped")
}
