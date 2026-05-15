package checks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ExecDocker is the production DockerClient. It shells out to the docker
// CLI on the host. It is intentionally minimal — full Docker SDK use is
// reserved for actual container invocation (see internal/dockerrun).
type ExecDocker struct {
	// Path overrides the docker binary path (default: "docker" via PATH).
	Path string
}

func (d *ExecDocker) bin() string {
	if d.Path != "" {
		return d.Path
	}
	return "docker"
}

// Version returns the docker server version string, or an error if the
// daemon is unreachable.
func (d *ExecDocker) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, d.bin(), "version", "--format", "{{.Server.Version}}").CombinedOutput() //nolint:gosec // d.bin() validated by caller
	if err != nil {
		return "", fmt.Errorf("docker version: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return "docker " + strings.TrimSpace(string(out)), nil
}

// ImageExists reports whether the named image reference is locally
// available. It returns false (without error) when the image is simply
// absent; it returns an error only on transport-level failures.
func (d *ExecDocker) ImageExists(ctx context.Context, ref string) (bool, error) {
	cmd := exec.CommandContext(ctx, d.bin(), "image", "inspect", ref) //nolint:gosec // ref originates from validated config
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if ok := isExitError(err, &exitErr); ok {
			// Image inspect returns non-zero when the image is missing;
			// other failure modes leak through as errors.
			return false, nil
		}
		return false, fmt.Errorf("docker image inspect: %w", err)
	}
	return true, nil
}

// OSEnv is the production EnvLookup wrapping os.LookupEnv.
type OSEnv struct{}

// Lookup delegates to os.LookupEnv.
func (OSEnv) Lookup(key string) (string, bool) {
	return osLookupEnv(key)
}
