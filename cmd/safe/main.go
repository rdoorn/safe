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
		doShell       bool
	)

	cmd := &cobra.Command{
		Use:                   "safe <agent> [agent args...]",
		Short:                 "Sandboxed Agent For Engineering",
		Long:                  "Run AI coding agents inside a hardened container with FQDN-anchored networking.",
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		SilenceErrors:         false,
		Version:               version.Version,
		Args:                  cobra.ArbitraryArgs,
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
			case doShell:
				return runAgent(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), xdg, cwd, defaultAgentName, nil, true)
			default:
				if len(args) == 0 {
					return cmd.Help()
				}
				return runAgent(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), xdg, cwd, args[0], args[1:], false)
			}
		},
	}
	cmd.SetVersionTemplate(fmt.Sprintf("safe %s\n", version.Version))

	cmd.PersistentFlags().String("config", "", "path to safe.yaml (default: XDG + cwd)")
	cmd.Flags().BoolVar(&doPrintConfig, "print-config", false, "print the merged config as YAML and exit")
	cmd.Flags().BoolVar(&doDoctor, "doctor", false, "run pre-flight checks and exit")
	cmd.Flags().BoolVar(&doShell, "shell", false, "open an interactive bash shell inside the sandbox")

	return cmd
}
