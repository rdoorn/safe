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
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			rw.Apply(r)
		},
		Transport: cfg.Transport,
	}
}
