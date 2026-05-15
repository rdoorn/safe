package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// configFilename is the canonical SAFE config file name in both the global
// (XDG) and per-project (cwd) locations.
const configFilename = "safe.yaml"

// LoadFile parses the YAML config at path. A missing file is not an error and
// returns an empty Config; this lets callers compose "global + project"
// loading without checking for either's existence separately.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed by us
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data)
}

// LoadAll returns the SAFE configs that exist for this invocation, in
// merge order (global first, project last). The caller is expected to feed
// the slice into Merge.
//
// xdgConfigDir is the value of os.UserConfigDir() (e.g. ~/.config). cwd is
// the directory the user invoked safe from. Either or both files may be
// missing; missing files are silently skipped.
func LoadAll(xdgConfigDir, cwd string) ([]*Config, error) {
	paths := []string{
		filepath.Join(xdgConfigDir, "safe", configFilename),
		filepath.Join(cwd, configFilename),
	}

	var configs []*Config
	for _, p := range paths {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		c, err := LoadFile(p)
		if err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, nil
}
