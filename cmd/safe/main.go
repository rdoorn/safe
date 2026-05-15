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
	var doPrintConfig bool

	cmd := &cobra.Command{
		Use:           "safe",
		Short:         "Sandboxed Agent For Engineering",
		Long:          "Run AI coding agents inside a hardened container with FQDN-anchored networking.",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version.Version,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if doPrintConfig {
				xdg, err := os.UserConfigDir()
				if err != nil {
					return fmt.Errorf("locate user config dir: %w", err)
				}
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("locate cwd: %w", err)
				}
				return printConfig(cmd.OutOrStdout(), xdg, cwd)
			}
			return cmd.Help()
		},
	}
	cmd.SetVersionTemplate(fmt.Sprintf("safe %s\n", version.Version))

	cmd.PersistentFlags().String("config", "", "path to safe.yaml (default: XDG + cwd)")
	cmd.Flags().BoolVar(&doPrintConfig, "print-config", false, "print the merged config as YAML and exit")

	return cmd
}
