// Package main is the entrypoint for the LLM-API key-holder proxy (safe-keyholder).
//
// safe-keyholder runs as user `keyholder` inside the SAFE container. It
// reads the real LLM API key from stdin once, then listens on
// 127.0.0.1:8443 and proxies requests to the configured upstream,
// substituting the auth header so the agent never sees the key.
package main

import (
	"context"
	"flag"
	"fmt"
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
)

func main() {
	var (
		configPath = flag.String("config", defaultConfigPath, "path to safe config")
		listenAddr = flag.String("listen", defaultListenAddr, "host:port to listen on")
		agentName  = flag.String("agent", "claude", "agent name to read from config")
	)
	flag.Parse()

	if err := run(*configPath, *listenAddr, *agentName); err != nil {
		fmt.Fprintln(os.Stderr, "safe-keyholder:", err)
		os.Exit(1)
	}
}

func run(configPath, listenAddr, agentName string) error {
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

	key, err := keyholder.Bootstrap(os.Stdin)
	if err != nil {
		return fmt.Errorf("read key from stdin: %w", err)
	}

	proxy := keyholder.NewProxy(keyholder.ProxyConfig{
		Key:        key,
		AuthHeader: authHeader,
		AuthScheme: agent.AuthScheme,
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

	fmt.Fprintln(os.Stderr, "safe-keyholder: listening on", listenAddr, "->", target.String())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}
