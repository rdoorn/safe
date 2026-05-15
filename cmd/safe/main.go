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
	var (
		doPrintConfig bool
		doDoctor      bool
	)

	cmd := &cobra.Command{
		Use:           "safe",
		Short:         "Sandboxed Agent For Engineering",
		Long:          "Run AI coding agents inside a hardened container with FQDN-anchored networking.",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			xdg, cwd, err := hostDirs()
			if err != nil {
				return err
			}

			switch {
			case doPrintConfig:
				return printConfig(cmd.OutOrStdout(), xdg, cwd)
			case doDoctor:
				return runDoctor(cmd.Context(), cmd.OutOrStdout(), xdg, cwd, resolveAgentName(args))
			default:
				return cmd.Help()
			}
		},
	}
	cmd.SetVersionTemplate(fmt.Sprintf("safe %s\n", version.Version))

	cmd.PersistentFlags().String("config", "", "path to safe.yaml (default: XDG + cwd)")
	cmd.Flags().BoolVar(&doPrintConfig, "print-config", false, "print the merged config as YAML and exit")
	cmd.Flags().BoolVar(&doDoctor, "doctor", false, "run pre-flight checks and exit")

	return cmd
}
