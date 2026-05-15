package checks

import (
	"errors"
	"os"
	"os/exec"
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
