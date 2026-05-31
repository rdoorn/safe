package keyholder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// ForceRefresher is implemented by token sources that can force a token
// refresh after the upstream rejects the current token with a 401. Only
// *OAuthTokenSource implements it; the static *Key does not, so apikey
// mode never takes the refresh-and-retry path.
type ForceRefresher interface {
	ForceRefresh(ctx context.Context) error
}

// refreshingTransport wraps a base RoundTripper. When the token source can
// force-refresh and the upstream answers 401, it refreshes the token,
// rewrites the auth header with the fresh value, and retries the request
// exactly once. This turns a mid-session token expiry into a transparent
// retry instead of a 401 that the agent surfaces as a forced re-login.
//
// If the refresh itself fails, the original 401 is returned untouched so
// the agent sees the genuine auth failure.
type refreshingTransport struct {
	base       http.RoundTripper
	token      TokenSource
	authHeader string
	authScheme string
}

// RoundTrip implements http.RoundTripper.
func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	refresher, ok := t.token.(ForceRefresher)
	if !ok {
		// apikey mode: nothing to refresh, forward unchanged.
		return t.base.RoundTrip(req)
	}

	// Buffer the body so the request can be replayed once on retry.
	// Anthropic requests are bounded JSON, not streaming uploads.
	body, err := drainBody(req)
	if err != nil {
		return nil, fmt.Errorf("buffer request body for retry: %w", err)
	}

	resp, err := t.base.RoundTrip(cloneWithBody(req, body))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	// 401: try a forced refresh. If it fails, hand the original 401 back
	// (its body is still intact — we have not read it).
	if rerr := refresher.ForceRefresh(req.Context()); rerr != nil {
		return resp, nil
	}
	// TODO(writeback): persist the rotated credentials to the host here once
	// the write-back channel lands (see oauth-token-writeback-design.md).

	// Discard the 401 response before replaying with the fresh token.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	retry := cloneWithBody(req, body)
	retry.Header.Set(t.authHeader, t.token.AuthHeaderValue(t.authScheme))
	return t.base.RoundTrip(retry)
}

// drainBody reads and closes req.Body, returning its bytes (nil for a
// bodyless request).
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	b, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	return b, nil
}

// cloneWithBody returns a shallow clone of req with a fresh reader over the
// buffered body, so the original request is never mutated across attempts.
func cloneWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	if body == nil {
		clone.Body = nil
		clone.ContentLength = 0
	} else {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	}
	return clone
}
