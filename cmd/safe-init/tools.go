package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/rdoorn/safe/internal/config"
)

// ensureProjectTools installs the per-project language-runtime versions
// requested in safe.yaml's agents.<name>.tools block. Installs happen as
// the agent uid (via stageAsAgent-style fork+exec) so the resulting
// files belong to the agent and live in the bind-mounted .safe/tools/
// project dir, persisting across container runs.
//
// First-run installs need network: pyenv builds Python from source
// (downloads from python.org); fnm downloads prebuilt Node tarballs
// (from nodejs.org). Both domains must be in the allowlist.
//
// A missing version field is not an error: SAFE just doesn't provision
// that runtime. Users can rely on whatever ships in the image.
func ensureProjectTools(agentName string) error {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	a, ok := cfg.Agents[agentName]
	if !ok {
		return nil
	}

	if v := a.Tools.Python; v != "" {
		if err := ensurePython(v); err != nil {
			return fmt.Errorf("python %s: %w", v, err)
		}
	}
	if v := a.Tools.Node; v != "" {
		if err := ensureNode(v); err != nil {
			return fmt.Errorf("node %s: %w", v, err)
		}
	}
	return nil
}

// ensurePython runs `pyenv install <version>` if the version isn't
// already in /opt/pyenv/versions. pyenv writes there directly because
// of the bind-mount.
func ensurePython(version string) error {
	target := filepath.Join("/opt/pyenv/versions", version)
	if _, err := os.Stat(target); err == nil {
		return nil // already installed
	}
	fmt.Fprintf(os.Stderr, "safe-init: installing python %s via pyenv (first run; may take 2-3 min)...\n", version)
	return runAsAgent("/opt/pyenv/bin/pyenv", []string{"install", "--skip-existing", version},
		[]string{"PYENV_ROOT=/opt/pyenv", "PATH=/opt/pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
}

// ensureNode runs `fnm install <version>` if not already present.
func ensureNode(version string) error {
	target := filepath.Join("/opt/fnm/node-versions", "v"+version, "installation")
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "safe-init: installing node %s via fnm (first run)...\n", version)
	return runAsAgent("/usr/local/bin/fnm", []string{"install", version},
		[]string{"FNM_DIR=/opt/fnm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
}

// runAsAgent executes cmd with args as uid 1000, merging the given env
// list with HOME/USER/LOGNAME. Used so installed files are owned by the
// agent and writable in the bind-mounted .safe/tools dirs.
func runAsAgent(bin string, args, extraEnv []string) error {
	cmd := exec.Command(bin, args...) //nolint:gosec // bin/args from constants + validated config
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{
		"HOME=/home/agent",
		"USER=agent",
		"LOGNAME=agent",
	}, extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: defaultAgentUID, Gid: defaultAgentGID, NoSetGroups: true},
	}
	return cmd.Run()
}
