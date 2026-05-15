package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/rdoorn/safe/internal/checks"
	"github.com/rdoorn/safe/internal/config"
)

const defaultAgentName = "claude"

// runDoctor executes pre-flight checks for the given agent and prints
// results in a stable, scriptable format.
func runDoctor(ctx context.Context, out io.Writer, xdgConfigDir, cwd, agentName string) error {
	configs, err := config.LoadAll(xdgConfigDir, cwd)
	if err != nil {
		return fmt.Errorf("load configs: %w", err)
	}
	merged := config.MergeAll(configs)

	deps := checks.Deps{
		Docker: &checks.ExecDocker{},
		Env:    checks.OSEnv{},
	}
	results := checks.Run(ctx, deps, merged, agentName)

	for _, r := range results {
		status := "FAIL"
		if r.OK {
			status = "OK"
		}
		if _, werr := fmt.Fprintf(out, "[%s] %-25s  %s\n", status, r.Name, r.Detail); werr != nil {
			return fmt.Errorf("write doctor output: %w", werr)
		}
	}

	if !checks.AllOK(results) {
		return checks.ErrFailed
	}
	return nil
}

// resolveAgentName picks which agent --doctor should validate. For now
// it defaults to "claude"; once `safe <agent>` is wired, callers can pass
// the explicit agent name in.
func resolveAgentName(args []string) string {
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	return defaultAgentName
}

// hostDirs returns the XDG config dir and the cwd, with errors mapped to
// a stable form for error-path tests.
func hostDirs() (xdg, cwd string, err error) {
	xdg, err = os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("locate user config dir: %w", err)
	}
	cwd, err = os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("locate cwd: %w", err)
	}
	return xdg, cwd, nil
}
