// Package dockerrun assembles the `docker run` argument vector that the
// safe CLI hands to the host's docker client.
package dockerrun

import (
	"fmt"

	"github.com/rdoorn/safe/internal/config"
)

// Inputs bundles everything BuildArgv needs.
type Inputs struct {
	Config         *config.Config
	AgentName      string
	AgentArgs      []string
	CWD            string
	RunID          string
	SocketDir      string
	SeccompProfile string
	HomeVolumeName string
	TTY            bool
	Shell          bool
	// MountFlags is the slice of "-v src:dst:opts" entries already
	// computed by customize.go for the active agent. Empty in tests
	// that don't exercise customization.
	MountFlags []string
}

// BuildArgv produces the full argv (starting with "docker" itself) that
// `safe` will exec. It is a pure function; no syscalls, no env reads.
func BuildArgv(in Inputs) ([]string, error) {
	if in.Config == nil {
		return nil, fmt.Errorf("nil config")
	}
	agent, ok := in.Config.Agents[in.AgentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not in registry", in.AgentName)
	}
	if agent.Image == "" {
		return nil, fmt.Errorf("agent %q has no image", in.AgentName)
	}

	mem := in.Config.Resources.Memory
	if mem == "" {
		mem = "4g"
	}
	pids := in.Config.Resources.PIDs
	if pids == 0 {
		pids = 256
	}
	homeVolume := in.HomeVolumeName
	if homeVolume == "" {
		homeVolume = "safe-cache-" + in.RunID
	}

	argv := []string{
		"docker", "run",
		"--rm",
		"--name", "safe-" + in.RunID,
		"--hostname", "safe",
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		// NB: we deliberately do NOT pass --security-opt no-new-privileges.
		// The kernel ignores file capabilities under no_new_privs, which
		// would break the cap_net_admin file cap on /usr/sbin/safe-dns.
		// The narrow protection no-new-privs gives (preventing the agent
		// from gaining caps by exec'ing a file-cap'd binary) is instead
		// achieved by chmod 0750 + chgrp firewall on safe-dns inside the
		// image — the agent uid can't exec safe-dns at all.
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m",
		"--tmpfs", "/run:rw,nosuid,nodev,noexec,size=64m",
		"--tmpfs", "/home/agent:rw,nosuid,nodev,size=512m",
		"--pids-limit", fmt.Sprintf("%d", pids),
		"--memory", mem,
		"--memory-swap", mem,
		"--network", "bridge",
		"--dns", "127.0.0.1",
		"--env-file", "/dev/null",
	}
	if in.TTY {
		argv = append(argv, "-it")
	} else {
		argv = append(argv, "-i")
	}
	if in.SeccompProfile != "" {
		argv = append(argv, "--security-opt", "seccomp="+in.SeccompProfile)
	}

	argv = append(argv,
		"-v", in.CWD+":/workspace",
		"-v", homeVolume+":/home/agent/.cache",
		"-v", in.SocketDir+":/run/safe",
	)
	argv = append(argv, in.MountFlags...)

	for _, k := range in.Config.EnvPassthrough {
		argv = append(argv, "-e", k)
	}

	if in.Shell {
		argv = append(argv, "--entrypoint", "/bin/bash", agent.Image)
	} else {
		argv = append(argv, agent.Image, in.AgentName)
		argv = append(argv, in.AgentArgs...)
	}

	return argv, nil
}
