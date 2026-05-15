// Package checks implements the pre-flight checks run by `safe --doctor`
// (and silently before every `safe <agent>` invocation).
package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/rdoorn/safe/internal/config"
)

// DockerClient is the subset of Docker functionality the checks need. It is
// abstracted so tests can substitute a fake without touching exec.Command.
type DockerClient interface {
	Version(ctx context.Context) (string, error)
	ImageExists(ctx context.Context, ref string) (bool, error)
}

// EnvLookup is the subset of os.LookupEnv used by the checks.
type EnvLookup interface {
	Lookup(key string) (string, bool)
}

// Deps bundles the side-effecting dependencies of the checks so they can be
// swapped out in tests.
type Deps struct {
	Docker DockerClient
	Env    EnvLookup
}

// Result is one check's outcome. Detail is a one-line explanation suitable
// for terminal output.
type Result struct {
	Name   string
	OK     bool
	Detail string
}

// Run executes all SAFE pre-flight checks for the given config + agent. It
// never short-circuits; every check is run so the user sees the full list
// of green/red items in one go.
func Run(ctx context.Context, deps Deps, cfg *config.Config, agentName string) []Result {
	results := []Result{
		dockerReachable(ctx, deps.Docker),
		configValid(cfg, agentName),
	}

	if a, ok := cfg.Agents[agentName]; ok {
		results = append(results, imagePresent(ctx, deps.Docker, a.Image))
		if a.AuthEnv != "" {
			results = append(results, envSet(deps.Env, a.AuthEnv))
		}
	}

	return results
}

func dockerReachable(ctx context.Context, dc DockerClient) Result {
	r := Result{Name: "docker reachable"}
	if dc == nil {
		r.Detail = "no docker client wired"
		return r
	}
	v, err := dc.Version(ctx)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	r.OK = true
	r.Detail = v
	return r
}

func imagePresent(ctx context.Context, dc DockerClient, ref string) Result {
	r := Result{Name: "image present"}
	if dc == nil {
		r.Detail = "no docker client wired"
		return r
	}
	ok, err := dc.ImageExists(ctx, ref)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	if !ok {
		r.Detail = fmt.Sprintf("image %s not pulled (run: docker pull %s)", ref, ref)
		return r
	}
	r.OK = true
	r.Detail = ref
	return r
}

func configValid(cfg *config.Config, agentName string) Result {
	r := Result{Name: "config valid"}
	if cfg == nil {
		r.Detail = "config is nil"
		return r
	}
	if err := config.Validate(cfg, agentName); err != nil {
		r.Detail = err.Error()
		return r
	}
	r.OK = true
	r.Detail = "schema and invariants satisfied"
	return r
}

func envSet(env EnvLookup, key string) Result {
	r := Result{Name: key + " set"}
	if env == nil {
		r.Detail = "no env lookup wired"
		return r
	}
	v, ok := env.Lookup(key)
	if !ok || v == "" {
		r.Detail = fmt.Sprintf("environment variable %s is not set on the host", key)
		return r
	}
	r.OK = true
	r.Detail = "present"
	return r
}

// AllOK returns true iff every result in rs is OK.
func AllOK(rs []Result) bool {
	for _, r := range rs {
		if !r.OK {
			return false
		}
	}
	return true
}

// ErrFailed is returned by a caller wrapping a failed check run for use as
// an exit-code carrier.
var ErrFailed = errors.New("preflight checks failed")
