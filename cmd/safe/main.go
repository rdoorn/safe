// Package main is the entrypoint for the safe host CLI.
package main

import (
	"fmt"
	"os"

	"github.com/rdoorn/safe/pkg/version"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "safe",
		Short:         "Sandboxed Agent For Engineering",
		Long:          "Run AI coding agents inside a hardened container with FQDN-anchored networking.",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version.Version,
	}
	cmd.SetVersionTemplate(fmt.Sprintf("safe %s\n", version.Version))

	cmd.PersistentFlags().String("config", "", "path to safe.yaml (default: XDG + cwd)")

	return cmd
}
