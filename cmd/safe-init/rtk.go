package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// rtkTelemetryEnv is set in both the rtk init subprocess and the agent process
// so that RTK never attempts telemetry calls (the container is firewalled).
const rtkTelemetryEnv = "RTK_TELEMETRY_DISABLED=1"

// initRTK runs `rtk init -g --auto-patch` as the agent uid so RTK can write
// its Claude Code PreToolUse hook into /home/agent/.claude/settings.json.
// RTK manages its own merge logic; if settings.json already exists (from
// a customization.settings mount) RTK merges into it.
//
// --auto-patch is mandatory: container startup is non-interactive, so the
// default `rtk init -g` settings.json prompt ("[y/N]") reads no stdin and
// defaults to N, silently leaving the hook uninstalled (no token savings).
//
// When running as root (the normal container case), the child is exec'd
// as uid 1000/gid 1000. When not root (developer test runs), credentials
// are not set and the child inherits the caller's uid.
//
// A non-zero exit is logged as a warning and does not abort startup —
// the agent starts regardless, just without RTK's hook.
func initRTK(binPath string) {
	fmt.Fprintln(os.Stderr, "safe-init: rtk: enabled, telemetry disabled")
	cmd := exec.Command(binPath, "init", "-g", "--auto-patch") //nolint:gosec // binPath is a constant at production call sites
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"HOME=/home/agent",
		rtkTelemetryEnv,
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
