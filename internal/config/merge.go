package config

// Merge layers overlay on top of base and returns a new Config. Neither
// input is mutated. The rules are:
//
//   - Slices append: overlay entries follow base entries.
//   - Maps merge per-key: overlay keys overwrite base keys, base-only keys
//     survive.
//   - Scalar fields (string, int, bool): overlay replaces base only if the
//     overlay value is non-zero. This lets a partial overlay leave most of
//     the base intact.
//   - The Customization struct is replaced as a whole if overlay has any
//     field set (so the user can switch a flag off in a project file by
//     explicitly setting another flag). If overlay's Customization is the
//     zero value, base wins.
//
// Either argument may be nil; nil is treated as an empty Config.
func Merge(base, overlay *Config) *Config {
	if base == nil {
		base = &Config{}
	}
	if overlay == nil {
		overlay = &Config{}
	}

	out := &Config{
		Agents:         mergeAgents(base.Agents, overlay.Agents),
		Allowlist:      appendStrings(base.Allowlist, overlay.Allowlist),
		UpstreamDNS:    appendStrings(base.UpstreamDNS, overlay.UpstreamDNS),
		Mounts:         appendStrings(base.Mounts, overlay.Mounts),
		EnvPassthrough: appendStrings(base.EnvPassthrough, overlay.EnvPassthrough),
		Resources:      mergeResources(base.Resources, overlay.Resources),
		Audit:          mergeAudit(base.Audit, overlay.Audit),
	}
	return out
}

// MergeAll folds a slice of configs into a single config by repeated
// Merge calls (left-fold, so the last entry has highest precedence).
func MergeAll(configs []*Config) *Config {
	out := &Config{}
	for _, c := range configs {
		out = Merge(out, c)
	}
	return out
}

func appendStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func mergeAgents(base, overlay map[string]Agent) map[string]Agent {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	out := make(map[string]Agent, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		if existing, ok := out[k]; ok {
			out[k] = mergeAgent(existing, v)
		} else {
			out[k] = v
		}
	}
	return out
}

func mergeAgent(base, overlay Agent) Agent {
	out := base
	if overlay.Image != "" {
		out.Image = overlay.Image
	}
	if overlay.Entrypoint != "" {
		out.Entrypoint = overlay.Entrypoint
	}
	if overlay.AuthEnv != "" {
		out.AuthEnv = overlay.AuthEnv
	}
	if overlay.BaseURLEnv != "" {
		out.BaseURLEnv = overlay.BaseURLEnv
	}
	if overlay.BaseURL != "" {
		out.BaseURL = overlay.BaseURL
	}
	if overlay.AuthHeader != "" {
		out.AuthHeader = overlay.AuthHeader
	}
	if overlay.AuthScheme != "" {
		out.AuthScheme = overlay.AuthScheme
	}
	out.LockedTools = appendStrings(out.LockedTools, overlay.LockedTools)
	out.Env = mergeStringMap(out.Env, overlay.Env)
	if overlay.Customization != (Customization{}) {
		out.Customization = overlay.Customization
	}
	return out
}

func mergeStringMap(base, overlay map[string]string) map[string]string {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func mergeResources(base, overlay Resources) Resources {
	out := base
	if overlay.Memory != "" {
		out.Memory = overlay.Memory
	}
	if overlay.PIDs != 0 {
		out.PIDs = overlay.PIDs
	}
	return out
}

func mergeAudit(base, overlay Audit) Audit {
	out := base
	if overlay.Enabled {
		out.Enabled = overlay.Enabled
	}
	if overlay.HostPath != "" {
		out.HostPath = overlay.HostPath
	}
	return out
}
