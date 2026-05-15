package keyholder_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/keyholder"
	"github.com/stretchr/testify/require"
)

func TestProxyForwardsAndRewrites(t *testing.T) {
	var sawAuth, sawHost, sawBody string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawHost = r.Host
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	target, _ := url.Parse(upstream.URL)
	p := keyholder.NewProxy(keyholder.ProxyConfig{
		Key:        keyholder.NewKey("sk-real"),
		AuthHeader: "Authorization",
		AuthScheme: "Bearer",
		Target:     target,
		// Trust the httptest TLS cert.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test only
	})

	front := httptest.NewServer(p)
	t.Cleanup(front.Close)

	req, _ := http.NewRequest("POST", front.URL+"/v1/messages", strings.NewReader(`{"hi":"there"}`))
	req.Header.Set("Authorization", "Bearer dummy")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "Bearer sk-real", sawAuth)
	require.Equal(t, target.Host, sawHost)
	require.Equal(t, `{"hi":"there"}`, sawBody)
}
