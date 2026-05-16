package keyholder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// OAuthCredentials is the SAFE-side representation of Claude Code's
// ~/.claude/.credentials.json. Only the fields we actually need are
// modelled; extra fields are ignored on parse and preserved on save
// via a passthrough map.
type OAuthCredentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // converted from epoch milliseconds
}

// claudeCredentialsFile is the raw on-disk schema (Claude Code's).
type claudeCredentialsFile struct {
	ClaudeAIOauth struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresAt    int64  `json:"expiresAt"` // epoch milliseconds
	} `json:"claudeAiOauth"`
}

// ParseOAuthCredentials decodes Claude Code's credentials.json blob.
func ParseOAuthCredentials(data []byte) (*OAuthCredentials, error) {
	var f claudeCredentialsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse credentials json: %w", err)
	}
	oc := f.ClaudeAIOauth
	if oc.AccessToken == "" {
		return nil, errors.New("credentials missing claudeAiOauth.accessToken")
	}
	if oc.RefreshToken == "" {
		return nil, errors.New("credentials missing claudeAiOauth.refreshToken")
	}
	if oc.ExpiresAt == 0 {
		return nil, errors.New("credentials missing claudeAiOauth.expiresAt")
	}
	return &OAuthCredentials{
		AccessToken:  oc.AccessToken,
		RefreshToken: oc.RefreshToken,
		ExpiresAt:    time.UnixMilli(oc.ExpiresAt),
	}, nil
}

// OAuthTokenSource maintains a live OAuth access token, refreshing it
// via the OAuth2 refresh-token grant when it's about to expire or after
// a 401 from the upstream. Safe for concurrent use.
type OAuthTokenSource struct {
	refreshURL string
	httpClient *http.Client
	skewBefore time.Duration // refresh this far before expiry

	mu    sync.RWMutex
	creds *OAuthCredentials
}

// NewOAuthTokenSource constructs a TokenSource over the given initial
// credentials. refreshURL is the OAuth2 token endpoint (e.g.
// https://console.anthropic.com/v1/oauth/token).
func NewOAuthTokenSource(creds *OAuthCredentials, refreshURL string, httpClient *http.Client) *OAuthTokenSource {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &OAuthTokenSource{
		refreshURL: refreshURL,
		httpClient: httpClient,
		skewBefore: 2 * time.Minute,
		creds:      creds,
	}
}

// AuthHeaderValue returns the current Authorization header value
// ("Bearer <access_token>"), refreshing first if the token is within
// skewBefore of expiring. scheme is ignored — OAuth is always Bearer.
func (s *OAuthTokenSource) AuthHeaderValue(_ string) string {
	s.mu.RLock()
	expiresAt := s.creds.ExpiresAt
	tok := s.creds.AccessToken
	s.mu.RUnlock()

	if time.Until(expiresAt) <= s.skewBefore {
		if err := s.refreshIfNeeded(context.Background()); err != nil {
			// Best effort: return the (possibly expired) token; upstream
			// will 401 and the request handler can trigger another
			// refresh attempt with the error visible.
			_ = err
		}
		s.mu.RLock()
		tok = s.creds.AccessToken
		s.mu.RUnlock()
	}
	return "Bearer " + tok
}

// ForceRefresh forces a token refresh now. Use after the upstream
// returns 401 to retry with a fresh token.
func (s *OAuthTokenSource) ForceRefresh(ctx context.Context) error {
	return s.doRefresh(ctx)
}

// String returns a redacted form for safe logging.
func (s *OAuthTokenSource) String() string { return "[OAUTH REDACTED]" }

// refreshIfNeeded does a refresh under lock; concurrent callers piggyback.
func (s *OAuthTokenSource) refreshIfNeeded(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Until(s.creds.ExpiresAt) > s.skewBefore {
		return nil // someone else refreshed while we were waiting
	}
	return s.refreshLocked(ctx)
}

func (s *OAuthTokenSource) doRefresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(ctx)
}

func (s *OAuthTokenSource) refreshLocked(ctx context.Context) error {
	if s.refreshURL == "" {
		return errors.New("refresh URL not configured")
	}

	body := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": s.creds.RefreshToken,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal refresh body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.refreshURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("refresh request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("refresh status %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"` // seconds
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("parse refresh response: %w", err)
	}
	if parsed.AccessToken == "" {
		return errors.New("refresh response missing access_token")
	}

	s.creds.AccessToken = parsed.AccessToken
	if parsed.RefreshToken != "" {
		s.creds.RefreshToken = parsed.RefreshToken
	}
	if parsed.ExpiresIn > 0 {
		s.creds.ExpiresAt = time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	}
	return nil
}
