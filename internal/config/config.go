// Package config defines the SAFE configuration schema and how it is parsed,
// loaded from disk, merged, and validated.
package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config is the top-level SAFE configuration as parsed from safe.yaml.
type Config struct {
	// ProjectID stabilizes the docker volume names SAFE uses for this
	// project's persistent caches. Defaults to a sha1 hash of the cwd.
	// Override only if you want to share volumes across machines or
	// across multiple working trees of the same project.
	ProjectID      string           `yaml:"project_id"`
	Agents         map[string]Agent `yaml:"agents"`
	Allowlist      []string         `yaml:"allowlist"`
	UpstreamDNS    []string         `yaml:"upstream_dns"`
	Mounts         []string         `yaml:"mounts"`
	EnvPassthrough []string         `yaml:"env_passthrough"`
	ExtraCaps      []string         `yaml:"extra_caps"`
	Resources      Resources        `yaml:"resources"`
	Audit          Audit            `yaml:"audit"`
	RTK            RTK              `yaml:"rtk"`
}

// Agent is the registry entry for one supported agent (e.g. claude, opencode).
//
// Authentication has two mutually-exclusive modes:
//   - API-key mode: set AuthEnv. The host env var holds a static key;
//     keyholder injects it as a fixed Authorization header.
//   - OAuth mode: set AuthCredentialsFile. The file (e.g.
//     ~/.claude/.credentials.json) holds OAuth tokens; keyholder reads
//     it at startup, injects the current access token, and refreshes
//     via AuthRefreshURL when the token expires.
//
// Validation rejects configs that set both or neither.
type Agent struct {
	Image               string            `yaml:"image"`
	Entrypoint          string            `yaml:"entrypoint"`
	AuthEnv             string            `yaml:"auth_env"`
	AuthCredentialsFile string            `yaml:"auth_credentials_file"`
	AuthRefreshURL      string            `yaml:"auth_refresh_url"`
	BaseURLEnv          string            `yaml:"base_url_env"`
	BaseURL             string            `yaml:"base_url"`
	AuthHeader          string            `yaml:"auth_header"`
	AuthScheme          string            `yaml:"auth_scheme"`
	LockedTools         []string          `yaml:"locked_tools"`
	Env                 map[string]string `yaml:"env"`
	Customization       Customization     `yaml:"customization"`
	// ExtraArgs are appended to the agent's argv on every run, before
	// any args the user passes on the command line. Common use: pass
	// flags like --dangerously-skip-permissions so claude doesn't prompt
	// for trust+tool permissions inside the SAFE sandbox.
	ExtraArgs []string `yaml:"extra_args"`
	// Tools requests specific language-runtime versions for this agent.
	// SAFE provisions them into <cwd>/.safe/tools/ (project-local) on
	// first run and reuses them on subsequent runs. Versions stay pinned
	// across container rebuilds.
	Tools AgentTools `yaml:"tools"`
}

// AgentTools pins language-runtime versions installed on demand by SAFE.
// Empty string = use whatever ships in the runtime image. Values must be
// exact versions (e.g., "3.14.0", "22.10.0"); ranges are not supported.
// If absent here, SAFE falls back to <cwd>/.python-version, .nvmrc, etc.
type AgentTools struct {
	Python string `yaml:"python"`
	Node   string `yaml:"node"`
}

// Customization controls which read-only files/subdirs from the host
// are bind-mounted into the container.
type Customization struct {
	Skills     bool `yaml:"skills"`
	Commands   bool `yaml:"commands"`
	ClaudeMD   bool `yaml:"claudemd"`
	Settings   bool `yaml:"settings"`
	Statusline bool `yaml:"statusline"`
	Hooks      bool `yaml:"hooks"`
	Plugins    bool `yaml:"plugins"`
	// State: bind-mount ~/.claude.json (the per-user state file with
	// theme prefs, project history, etc.) read-only. Lets claude skip
	// the theme prompt every session. RO means claude can't update it
	// from inside the container — change it via host claude instead.
	State bool `yaml:"state"`
}

// Resources is the Docker resource budget.
type Resources struct {
	Memory string `yaml:"memory"`
	PIDs   int    `yaml:"pids"`
}

// Audit configures the host-side audit log destination.
type Audit struct {
	Enabled  bool   `yaml:"enabled"`
	HostPath string `yaml:"host_path"`
}

// RTK controls whether RTK (Rust Token Killer) is enabled for the agent.
// RTK reduces LLM token consumption by filtering command output.
// Defaults to enabled when absent.
type RTK struct {
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled returns true when RTK is active. Nil (absent from config) means
// enabled — RTK is opt-out, not opt-in.
func (r RTK) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// Parse decodes YAML bytes into a Config.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}
