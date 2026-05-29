package dockerrun

// TerminalEnvPassthroughDefaults are env vars that SAFE always passes
// through from the host into the container, on top of whatever the
// user listed in safe.yaml's env_passthrough.
//
// These exist because claude code (and other TUI agents) reads them
// to decide which terminal features to enable — most importantly the
// kitty keyboard protocol, which is what makes shift+enter
// distinguishable from enter. Without TERM_PROGRAM set, claude falls
// back to a generic xterm assumption and shift+enter becomes a no-op.
//
// None of these vars carry secrets; they identify the host terminal
// emulator. They're hardcoded rather than added to env_passthrough's
// YAML default so existing user configs pick up the fix without
// requiring a safe.yaml edit.
var TerminalEnvPassthroughDefaults = []string{
	"TERM",
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"COLORTERM",
}

// mergeEnvPassthrough returns the union of user's list and the
// terminal defaults, preserving user order first and skipping
// duplicates (case-sensitive — env var names are case-sensitive).
func mergeEnvPassthrough(user []string) []string {
	seen := make(map[string]struct{}, len(user)+len(TerminalEnvPassthroughDefaults))
	out := make([]string, 0, len(user)+len(TerminalEnvPassthroughDefaults))
	for _, k := range user {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for _, k := range TerminalEnvPassthroughDefaults {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}
