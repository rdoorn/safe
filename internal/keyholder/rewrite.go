// Package keyholder implements the in-container HTTP proxy that injects
// the LLM API key. It is the only process inside the SAFE container that
// holds the real key in memory; the agent receives a dummy value and
// routes its requests through this proxy.
package keyholder

import (
	"net/http"
	"net/url"
)

// Key is an opaque holder for the real API key. It hides the secret from
// every code path except AuthHeaderValue, including fmt-printing.
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
// real LLM endpoint with the real key.
type Rewriter struct {
	// Key holds the real auth secret.
	Key *Key
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

	// Set the chosen header with the real key.
	r.Header.Set(rw.AuthHeader, rw.Key.AuthHeaderValue(rw.AuthScheme))

	// Rewrite destination to the upstream.
	r.URL.Scheme = rw.Target.Scheme
	r.URL.Host = rw.Target.Host
	r.Host = rw.Target.Host
}
