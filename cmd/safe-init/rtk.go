package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const rtkBin = "/usr/local/bin/rtk"

// initRTK runs `rtk init -g` as the agent uid so RTK can write its
// Claude Code PreToolUse hook into /home/agent/.claude/settings.json.
// RTK manages its own merge logic; if settings.json already exists (from
// a customization.settings mount) RTK merges into it.
//
// A non-zero exit is logged as a warning and does not abort startup —
// the agent starts regardless, just without RTK's hook.
func initRTK(binPath string) {
	fmt.Fprintln(os.Stderr, "safe-init: rtk: enabled, telemetry disabled")
	cmd := exec.Command(binPath, "init", "-g") //nolint:gosec // binPath is a constant at production call sites
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"HOME=/home/agent",
		"RTK_TELEMETRY_DISABLED=1",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if os.Getuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         defaultAgentUID,
				Gid:         defaultAgentGID,
				NoSetGroups: true,
			},
		}
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-init: rtk: hook init failed:", err, "(continuing)")
		return
	}
	fmt.Fprintln(os.Stderr, "safe-init: rtk: hook initialized")
}
