// Package keyholder implements the in-container HTTP proxy that injects
// the LLM API key. It is the only process inside the SAFE container that
// holds the real key in memory; the agent receives a dummy value and
// routes its requests through this proxy.
package keyholder

import (
	"fmt"
	"net/http"
	"net/url"
)

// TokenSource is anything that knows the current auth header value.
// Implementations include Key (static API key, returns the same value
// every call) and OAuthTokenSource (returns the current access token,
// refreshing it when it's near expiry).
type TokenSource interface {
	// AuthHeaderValue returns the value to put in the configured auth
	// header. scheme is the desired prefix ("Bearer", "" for raw).
	// OAuth sources ignore scheme — they always use "Bearer".
	AuthHeaderValue(scheme string) string
	fmt.Stringer
}

// Key is an opaque holder for a static API key. It hides the secret
// from every code path except AuthHeaderValue, including fmt-printing.
type Key struct {
	v string
}

// NewKey wraps a raw secret in a Key.
func NewKey(secret string) *Key { return &Key{v: secret} }

// String returns a redacted form so accidental %v / %s never leaks the
// secret into logs.
func (k *Key) String() string { return "[REDACTED]" }

// AuthHeaderValue returns the value to place in the configured auth
// header. When scheme is empty (x-api-key style) the secret is returned
// bare; otherwise the scheme is prepended ("Bearer sk-…").
func (k *Key) AuthHeaderValue(scheme string) string {
	if scheme == "" {
		return k.v
	}
	return scheme + " " + k.v
}

// Rewriter rewrites an inbound request so it can be forwarded to the
// real LLM endpoint with the real auth header.
type Rewriter struct {
	// Token is the live source of the auth header value. Called on every
	// proxied request so token rotation (OAuth) is picked up automatically.
	Token TokenSource
	// AuthHeader is the header name to set (e.g. "Authorization", "x-api-key").
	AuthHeader string
	// AuthScheme is the scheme prefix (e.g. "Bearer"). Empty for raw headers.
	AuthScheme string
	// Target is the upstream base URL. Only the Scheme and Host are used;
	// the request's path/query are preserved.
	Target *url.URL
}

// Apply mutates r in place so it is ready to be forwarded by an
// httputil.ReverseProxy.
func (rw *Rewriter) Apply(r *http.Request) {
	// Strip any auth headers the agent provided.
	r.Header.Del("Authorization")
	r.Header.Del("x-api-key")
	r.Header.Del("X-Api-Key")

	// Set the chosen header with the live token value.
	r.Header.Set(rw.AuthHeader, rw.Token.AuthHeaderValue(rw.AuthScheme))

	// Rewrite destination to the upstream.
	r.URL.Scheme = rw.Target.Scheme
	r.URL.Host = rw.Target.Host
	r.Host = rw.Target.Host
}
