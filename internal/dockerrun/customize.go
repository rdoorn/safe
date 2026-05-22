package dockerrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rdoorn/safe/internal/config"
)

// claudeMount describes one opt-in subpath of the user's ~/.claude/ tree.
type claudeMount struct {
	srcRel  string // path under ~/.claude on the host
	dstAbs  string // absolute path inside the container
	wantDir bool   // true if the source must be a directory; false for a file
}

// claudeMounts is the closed list of allowed customization mounts. Adding
// new entries is a code change on purpose: a stray .credentials.json that
// happens to live somewhere SAFE didn't whitelist will never be mounted.
// settings.json and CLAUDE.md are NOT in this list: they're staged via
// host-side copies (cmd/safe/run.go) so SAFE can inject content
// (skipDangerousModePermissionPrompt for settings, sandbox-policy
// preamble for CLAUDE.md) without round-tripping through the host file.
//
// The statusline script (whatever filename the user picked) is also
// NOT here. ExpandStatuslineMounts parses settings.json's
// statusLine.command field and mounts the referenced ~/.claude/*
// path(s) dynamically — see that function.
var claudeMounts = []claudeMount{
	{srcRel: "skills", dstAbs: "/home/agent/.claude/skills", wantDir: true},
	{srcRel: "commands", dstAbs: "/home/agent/.claude/commands", wantDir: true},
	{srcRel: "hooks", dstAbs: "/home/agent/.claude/hooks", wantDir: true},
	{srcRel: "plugins", dstAbs: "/home/agent/.claude/plugins", wantDir: true},
}

// gateFor returns the boolean field of c that gates the named mount.
func gateFor(c config.Customization, m claudeMount) bool {
	switch m.srcRel {
	case "skills":
		return c.Skills
	case "commands":
		return c.Commands
	case "hooks":
		return c.Hooks
	case "plugins":
		return c.Plugins
	default:
		return false
	}
}

// ExpandMounts returns "-v src:dst:ro" flags for every opt-in
// customization that (a) is enabled in c, (b) exists on the host, and
// (c) is allowed by the hardcoded mount list. The denylist is enforced
// by construction: anything not in claudeMounts simply cannot be mounted.
func ExpandMounts(claudeDir string, c config.Customization) []string {
	var out []string
	for _, m := range claudeMounts {
		if !gateFor(c, m) {
			continue
		}
		src := filepath.Join(claudeDir, m.srcRel)
		info, err := os.Stat(src)
		if err != nil {
			continue
		}
		if m.wantDir != info.IsDir() {
			continue
		}
		out = append(out, "-v", src+":"+m.dstAbs+":ro")
	}
	return out
}

// statuslineTokenRE matches `~/.claude/<path>` tokens inside a free-form
// shell command. We deliberately require the `~/.claude/` prefix so we
// don't accidentally mount paths the user typed for other reasons.
// Stops at whitespace or shell quote chars.
var statuslineTokenRE = regexp.MustCompile(`~/\.claude/[^\s'"` + "`" + `;|&]+`)

// ExpandStatuslineMounts reads the host's ~/.claude/settings.json,
// parses settings.statusLine.command (a free-form shell command), and
// returns bind-mount flags for every `~/.claude/<path>` referenced
// there. claude's statusline script can have any filename the user
// picked, so the only authoritative source is what settings.json says.
//
// Gated on Customization.Statusline — if false, returns nil even if
// the user has a statusLine block in settings.
//
// Mounts are read-only. Sources that don't exist on the host are
// silently skipped (matches ExpandMounts's behavior).
func ExpandStatuslineMounts(claudeDir string, c config.Customization) []string {
	if !c.Statusline {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(claudeDir, "settings.json")) //nolint:gosec // user's own home
	if err != nil {
		return nil
	}
	var settings struct {
		StatusLine struct {
			Command string `json:"command"`
		} `json:"statusLine"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil
	}
	cmd := settings.StatusLine.Command
	if cmd == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range statuslineTokenRE.FindAllString(cmd, -1) {
		if seen[tok] {
			continue
		}
		seen[tok] = true
		rel := strings.TrimPrefix(tok, "~/.claude/")
		src := filepath.Join(claudeDir, rel)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := "/home/agent/.claude/" + rel
		out = append(out, "-v", src+":"+dst+":ro")
	}
	return out
}
