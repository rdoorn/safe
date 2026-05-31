package keyholder

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ProxyConfig holds everything NewProxy needs.
type ProxyConfig struct {
	Token      TokenSource
	AuthHeader string
	AuthScheme string
	Target     *url.URL
	// Transport is optional; nil falls back to http.DefaultTransport.
	Transport http.RoundTripper
}

// NewProxy returns an httputil.ReverseProxy configured to:
//   - rewrite every inbound request via Rewriter.Apply, and
//   - forward to the configured upstream.
func NewProxy(cfg ProxyConfig) *httputil.ReverseProxy {
	rw := &Rewriter{
		Token:      cfg.Token,
		AuthHeader: cfg.AuthHeader,
		AuthScheme: cfg.AuthScheme,
		Target:     cfg.Target,
	}
	// When the token source can force-refresh (oauth mode), wrap the base
	// transport so a mid-session 401 triggers a refresh + single retry
	// instead of bubbling up to the agent as a forced re-login. apikey mode
	// has no refresh path and is left untouched.
	transport := cfg.Transport
	if _, ok := cfg.Token.(ForceRefresher); ok {
		base := cfg.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		transport = &refreshingTransport{
			base:       base,
			token:      cfg.Token,
			authHeader: cfg.AuthHeader,
			authScheme: cfg.AuthScheme,
		}
	}
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			rw.Apply(r)
		},
		Transport: transport,
	}
}
