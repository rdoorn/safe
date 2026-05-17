package checks

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// osLookupEnv is a tiny shim so checks_test.go can stay free of the os
// package import on the production lookup. (No mocking needed here; the
// tests use their own fake EnvLookup.)
func osLookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

func isExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// osStat wraps os.Stat so tests can substitute. For now it's a direct
// passthrough; the OAuth credentials check uses it.
var osStat = os.Stat

// expandHomeDir resolves a leading "~/" or "~" against $HOME.
func expandHomeDir(p string) string {
	if p == "~" {
		h, _ := os.UserHomeDir()
		return h
	}
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return h + "/" + p[2:]
	}
	return p
}
