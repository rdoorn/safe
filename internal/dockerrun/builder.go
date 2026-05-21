// Package dockerrun assembles the `docker run` argument vector that the
// safe CLI hands to the host's docker client.
package dockerrun

import (
	"crypto/sha1" //nolint:gosec // not for security; stable short hash of cwd path
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/rdoorn/safe/internal/config"
)

// projectHash returns a stable 12-char hex identifier for a project path.
// Used as the docker-volume-name suffix; the value is not security-sensitive.
func projectHash(cwd string) string {
	h := sha1.Sum([]byte(cwd)) //nolint:gosec // see top-level comment
	return hex.EncodeToString(h[:6])
}

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
func BuildArgv(in Inputs) ([]string, error) { //nolint:gocyclo // unavoidable branchy assembly of docker argv; splitting hurts readability more than it helps
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
	// Docker named-volume keys for per-project persistent state. Keyed
	// on a stable identifier (Config.ProjectID, default sha1 of CWD) so
	// the volumes survive across `safe claude` invocations of the same
	// project. RunID is per-invocation and would create a fresh empty
	// volume each time.
	projectKey := in.Config.ProjectID
	if projectKey == "" {
		projectKey = projectHash(in.CWD)
	}
	homeVolume := in.HomeVolumeName
	if homeVolume == "" {
		homeVolume = "safe-cache-" + projectKey
	}
	claudeProjectsVolume := "safe-claude-" + projectKey

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
		// CHOWN: safe-init uses this once at startup to chown
		// /home/agent/.claude (auto-created by docker as root when
		// resolving bind-mount parent paths) over to uid 1000. Without
		// this, claude can't write its own state/credentials into its
		// own home dir.
		"--cap-add", "CHOWN",
		// DAC_OVERRIDE: safe-init (root inside container) needs to
		// write into /home/agent (mode 755 owned by uid 1000) during
		// staging. Without this, Linux DAC blocks root because root
		// matches the "other" class on a 755 dir. The agent uid never
		// has this cap (we drop it from the bounding set in
		// hardenAgentSubtree before the agent exec).
		"--cap-add", "DAC_OVERRIDE",
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
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=512m",
		"--tmpfs", "/run:rw,nosuid,nodev,noexec,size=64m",
		// mode=755 (not 700) so safe-init (uid 0, no CAP_DAC_OVERRIDE) can
		// traverse /home/agent to chown the .claude subdir over to agent.
		// Files inside /home/agent are still owner-protected (claude writes
		// .credentials.json mode 0600), so other in-container uids can list
		// but not read contents.
		"--tmpfs", "/home/agent:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=755",
		"--tmpfs", "/var/log/safe:rw,nosuid,nodev,uid=200,gid=200,size=64m",
		"--pids-limit", fmt.Sprintf("%d", pids),
		"--memory", mem,
		"--memory-swap", mem,
		"--network", "bridge",
		"--dns", "127.0.0.1",
		"--env-file", "/dev/null",
	)
	// Keyholder is used in both auth modes. In API-key mode it holds the
	// static key in process memory; in OAuth mode it holds the access +
	// refresh tokens and refreshes them as they expire. Either way the
	// agent uid never sees the real credential — every request flows
	// through keyholder's proxy on 127.0.0.1:8443.
	useKeyholder := KeyholderEnabled
	if useKeyholder {
		argv = append(argv, "-p", "127.0.0.1:0:"+BootstrapPort+"/tcp")
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
		"-v", claudeProjectsVolume+":/home/agent/.claude/projects",
		"-v", in.ConfigDir+":/etc/safe:ro",
		// Project-local tool versions. SAFE provisions pyenv/fnm into
		// these dirs on first request and reuses on subsequent runs.
		// The dirs are inside the project's .safe/tools/ so they're
		// gitignored and follow the project.
		"-v", in.CWD+"/.safe/tools/python:/opt/pyenv/versions",
		"-v", in.CWD+"/.safe/tools/node:/opt/fnm/node-versions",
		// Start the agent process inside the project mount. Without
		// this, claude (and friends) default to / and prompt the user
		// to confirm trust of the rootfs.
		"-w", "/workspace",
	)
	argv = append(argv, in.MountFlags...)

	for _, k := range in.Config.EnvPassthrough {
		argv = append(argv, "-e", k)
	}

	if useKeyholder {
		argv = appendAgentEnv(argv, agent)
	} else {
		// OAuth mode (or keyholder globally disabled): still emit agent.Env
		// (DISABLE_TELEMETRY, CLAUDE_CODE_DISABLE_AUTOUPDATER, etc.) but
		// skip BASE_URL / dummy auth overrides. claude uses its image
		// defaults and does in-container OAuth.
		argv = appendAgentEnvOnly(argv, agent)
	}

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
//   - a dummy placeholder for the agent's auth env var. claude refuses
//     to start in EITHER mode without a credential of some kind, even
//     when ANTHROPIC_BASE_URL points at the keyholder. The placeholder
//     env var name is agent.AuthEnv if set (API-key mode), otherwise
//     "ANTHROPIC_API_KEY" (the canonical claude env var, used in OAuth
//     mode where the real credential lives in keyholder's memory and
//     never flows through this env var). The keyholder strips and
//     replaces the Authorization header in flight regardless.
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

	// Pick which env var carries the dummy auth placeholder. claude
	// needs SOMETHING in this var to make the call; keyholder strips
	// and substitutes the real credential in flight.
	//
	//   API-key mode (agent.AuthEnv set):
	//     use the configured env var name (e.g. ANTHROPIC_API_KEY).
	//   OAuth mode (agent.AuthCredentialsFile set):
	//     use ANTHROPIC_AUTH_TOKEN (a Bearer-token source). NOT
	//     ANTHROPIC_API_KEY — claude prompts "Detected a custom API
	//     key in your environment" on ANTHROPIC_API_KEY but treats
	//     ANTHROPIC_AUTH_TOKEN as a trusted OAuth Bearer source.
	authEnv := agent.AuthEnv
	if authEnv == "" {
		authEnv = "ANTHROPIC_AUTH_TOKEN"
	}
	argv = append(argv, "-e", authEnv+"=dummy")
	return argv
}

// appendAgentEnvOnly emits ONLY agent.Env (sorted keys). Used while the
// keyholder bootstrap is disabled (see KeyholderEnabled in constants.go):
// the agent talks to upstream directly with whatever credentials its
// image happens to find. Bring this back into appendAgentEnv once
// keyholder is re-enabled.
func appendAgentEnvOnly(argv []string, agent config.Agent) []string {
	envKeys := make([]string, 0, len(agent.Env))
	for k := range agent.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		argv = append(argv, "-e", k+"="+agent.Env[k])
	}
	return argv
}
