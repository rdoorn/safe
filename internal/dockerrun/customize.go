package dockerrun

import (
	"os"
	"path/filepath"

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
var claudeMounts = []claudeMount{
	{srcRel: "skills", dstAbs: "/home/agent/.claude/skills", wantDir: true},
	{srcRel: "commands", dstAbs: "/home/agent/.claude/commands", wantDir: true},
	{srcRel: "CLAUDE.md", dstAbs: "/home/agent/.claude/CLAUDE.md", wantDir: false},
	{srcRel: "settings.json", dstAbs: "/home/agent/.claude/settings.json", wantDir: false},
	{srcRel: "statusline.sh", dstAbs: "/home/agent/.claude/statusline.sh", wantDir: false},
	{srcRel: "hooks", dstAbs: "/home/agent/.claude/hooks", wantDir: true},
	{srcRel: "plugins", dstAbs: "/home/agent/.claude/plugins", wantDir: true},
	{srcRel: ".credentials.json", dstAbs: "/home/agent/.claude/.credentials.json", wantDir: false},
}

// gateFor returns the boolean field of c that gates the named mount.
func gateFor(c config.Customization, m claudeMount) bool {
	switch m.srcRel {
	case "skills":
		return c.Skills
	case "commands":
		return c.Commands
	case "CLAUDE.md":
		return c.ClaudeMD
	case "settings.json":
		return c.Settings
	case "statusline.sh":
		return c.Statusline
	case "hooks":
		return c.Hooks
	case "plugins":
		return c.Plugins
	case ".credentials.json":
		return c.Credentials
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
