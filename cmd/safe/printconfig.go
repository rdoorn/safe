package main

import (
	"fmt"
	"io"

	"github.com/rdoorn/safe/internal/config"
	"gopkg.in/yaml.v3"
)

// printConfig loads, merges, and serializes the SAFE config to out as
// YAML. xdgConfigDir is the global config root (typically os.UserConfigDir).
// cwd is the directory the user invoked safe from.
func printConfig(out io.Writer, xdgConfigDir, cwd string) error {
	configs, err := config.LoadAll(xdgConfigDir, cwd)
	if err != nil {
		return fmt.Errorf("load configs: %w", err)
	}
	merged := config.MergeAll(configs)

	data, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
