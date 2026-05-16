// Package main is the entrypoint for the LLM-API key-holder proxy (safe-keyholder).
//
// safe-keyholder runs as user `keyholder` inside the SAFE container. It
// reads the agent's auth secret from stdin once, then listens on
// 127.0.0.1:8443 and proxies requests to the configured upstream,
// substituting the auth header so the agent never sees the secret.
//
// Two auth modes:
//
//   - --mode=apikey  (default): stdin is a single line containing a
//     static API key. Injected verbatim as the configured auth header.
//
//   - --mode=oauth: stdin is the full Claude Code credentials.json JSON
//     blob. Keyholder parses out the access/refresh tokens, uses the
//     access token as a Bearer header, and refreshes against the OAuth
//     refresh endpoint when the token expires.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rdoorn/safe/internal/config"
	"github.com/rdoorn/safe/internal/keyholder"
)

const (
	defaultConfigPath = "/etc/safe/config.yaml"
	defaultListenAddr = "127.0.0.1:8443"
	defaultShutdown   = 5 * time.Second
	defaultRefreshURL = "https://console.anthropic.com/v1/oauth/token"
	authModeAPIKey    = "apikey"
	authModeOAuth     = "oauth"
)

func main() {
	var (
		configPath = flag.String("config", defaultConfigPath, "path to safe config")
		listenAddr = flag.String("listen", defaultListenAddr, "host:port to listen on")
		agentName  = flag.String("agent", "claude", "agent name to read from config")
		mode       = flag.String("mode", authModeAPIKey, "auth mode: apikey | oauth")
	)
	flag.Parse()

	if err := run(*configPath, *listenAddr, *agentName, *mode); err != nil {
		fmt.Fprintln(os.Stderr, "safe-keyholder:", err)
		os.Exit(1)
	}
}

func run(configPath, listenAddr, agentName, mode string) error {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	agent, ok := cfg.Agents[agentName]
	if !ok {
		return fmt.Errorf("agent %q not in config", agentName)
	}
	if agent.BaseURL == "" {
		return fmt.Errorf("agent %q: base_url is required", agentName)
	}
	target, err := url.Parse(agent.BaseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	authHeader := agent.AuthHeader
	if authHeader == "" {
		authHeader = "Authorization"
	}

	token, scheme, err := buildTokenSource(mode, agent, os.Stdin)
	if err != nil {
		return fmt.Errorf("build token source: %w", err)
	}

	proxy := keyholder.NewProxy(keyholder.ProxyConfig{
		Token:      token,
		AuthHeader: authHeader,
		AuthScheme: scheme,
		Target:     target,
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), defaultShutdown)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintln(os.Stderr, "safe-keyholder: listening on", listenAddr, "->", target.String(), "(mode:", mode+")")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// buildTokenSource constructs the right keyholder.TokenSource for the
// chosen auth mode and reads any required secrets from stdin.
func buildTokenSource(mode string, agent config.Agent, stdin io.Reader) (keyholder.TokenSource, string, error) {
	switch mode {
	case authModeAPIKey:
		key, err := keyholder.Bootstrap(stdin)
		if err != nil {
			return nil, "", fmt.Errorf("read key from stdin: %w", err)
		}
		return key, agent.AuthScheme, nil

	case authModeOAuth:
		blob, err := io.ReadAll(bufio.NewReader(stdin))
		if err != nil {
			return nil, "", fmt.Errorf("read credentials from stdin: %w", err)
		}
		creds, err := keyholder.ParseOAuthCredentials(blob)
		if err != nil {
			return nil, "", fmt.Errorf("parse credentials: %w", err)
		}
		refreshURL := agent.AuthRefreshURL
		if refreshURL == "" {
			refreshURL = defaultRefreshURL
		}
		ts := keyholder.NewOAuthTokenSource(creds, refreshURL, nil)
		// OAuth always uses "Bearer" regardless of agent.AuthScheme.
		return ts, "Bearer", nil

	default:
		return nil, "", fmt.Errorf("unknown auth mode %q (expected apikey or oauth)", mode)
	}
}
