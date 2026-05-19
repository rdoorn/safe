// Package dockerrun assembles the `docker run` argument vector that the
// safe CLI hands to the host's docker client.
package dockerrun

import (
	"fmt"
	"sort"

	"github.com/rdoorn/safe/internal/config"
)

// Inputs bundles everything BuildArgv needs.
type Inputs struct {
	Config         *config.Config
	AgentName      string
	AgentArgs      []string
	CWD            string
	RunID          string
	SeccompProfile string
	HomeVolumeName string
	TTY            bool
	Shell          bool
	// MountFlags is the slice of "-v src:dst:opts" entries already
	// computed by customize.go for the active agent. Empty in tests
	// that don't exercise customization.
	MountFlags []string
	// ConfigDir is the host directory holding the merged config.yaml.
	// Bind-mounted read-only at /etc/safe inside the container.
	ConfigDir string
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
	// ConfigDir is validated LAST so existing negative tests for missing
	// agent/image keep tripping their own errors without needing it set.
	if in.ConfigDir == "" {
		return nil, fmt.Errorf("config dir is required")
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
		// Required caps for SAFE's uid-separation architecture:
		//   NET_ADMIN: safe-dns manages nftables sets at runtime.
		//   SETUID/SETGID: safe-init (PID 1, root) spawns workers as
		//     uids 200/201/1000 — without these, setresuid in the child
		//     EPERMs even from root.
		//   KILL: safe-init signals cross-uid children in supervise().
		"--cap-add", "NET_ADMIN",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "KILL",
	}
	// Opt-in extras from config. Validated against allowedExtraCaps at
	// load time, so anything reaching here is one of SYS_ADMIN, SYS_PTRACE,
	// or NET_BIND_SERVICE. Slice order is preserved; duplicates are not
	// deduped (docker treats repeated --cap-add idempotently).
	for _, c := range in.Config.ExtraCaps {
		argv = append(argv, "--cap-add", c)
	}
	argv = append(argv,
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
		"--tmpfs", "/var/log/safe:rw,nosuid,nodev,uid=200,gid=200,size=64m",
		"--pids-limit", fmt.Sprintf("%d", pids),
		"--memory", mem,
		"--memory-swap", mem,
		"--network", "bridge",
		"-p", "127.0.0.1:0:"+BootstrapPort+"/tcp",
		"--dns", "127.0.0.1",
		"--env-file", "/dev/null",
	)
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
		"-v", in.ConfigDir+":/etc/safe:ro",
	)
	argv = append(argv, in.MountFlags...)

	for _, k := range in.Config.EnvPassthrough {
		argv = append(argv, "-e", k)
	}

	argv = appendAgentEnv(argv, agent)

	if in.Shell {
		argv = append(argv, "--entrypoint", "/bin/bash", agent.Image)
	} else {
		argv = append(argv, agent.Image, in.AgentName)
		argv = append(argv, in.AgentArgs...)
	}

	return argv, nil
}

// appendAgentEnv emits the per-agent env block:
//   - agent.Env entries (sorted key order for deterministic argv);
//   - the keyholder base URL on agent.BaseURLEnv (default
//     ANTHROPIC_BASE_URL), emitted AFTER agent.Env so docker's last-wins
//     semantics make the keyholder URL win if the user happens to set
//     the same key in agent.Env; the port matches
//     cmd/safe-keyholder/main.go defaultListenAddr;
//   - in API-key mode (agent.AuthEnv set), a dummy value on AuthEnv so
//     the real key (held by keyholder) is the only way out. OAuth mode
//     has no env-var-named API key to dummy out.
func appendAgentEnv(argv []string, agent config.Agent) []string {
	envKeys := make([]string, 0, len(agent.Env))
	for k := range agent.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		argv = append(argv, "-e", k+"="+agent.Env[k])
	}

	baseURLEnv := agent.BaseURLEnv
	if baseURLEnv == "" {
		baseURLEnv = "ANTHROPIC_BASE_URL"
	}
	argv = append(argv, "-e", baseURLEnv+"=http://127.0.0.1:8443")

	if agent.AuthEnv != "" {
		argv = append(argv, "-e", agent.AuthEnv+"=dummy")
	}
	return argv
}
