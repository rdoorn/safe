package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner abstracts how nft is invoked so unit tests can verify the
// command/arguments/stdin without shelling out.
type Runner interface {
	Run(ctx context.Context, cmd string, args []string, stdin string) (stdout, stderr string, err error)
}

// ApplyOptions parameterises an Apply call.
type ApplyOptions struct {
	NFTPath string // path to the nft binary; defaults to DefaultNFTPath()
	Runner  Runner // override for tests; defaults to ExecRunner{}
}

// Apply atomically loads the rendered Ruleset via `nft -f -`. Atomicity
// comes for free: nft applies the entire script in one transaction.
func Apply(ctx context.Context, rs Ruleset, opts ApplyOptions) error {
	if opts.NFTPath == "" {
		opts.NFTPath = DefaultNFTPath()
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}

	script := Render(rs)
	_, stderr, err := opts.Runner.Run(ctx, opts.NFTPath, []string{"-f", "-"}, script)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft: %s", msg)
	}
	return nil
}

// DefaultNFTPath is the absolute path of nft in the SAFE runtime image
// (Debian-based).
func DefaultNFTPath() string {
	return "/usr/sbin/nft"
}

// ExecRunner is the production Runner that shells out via os/exec.
type ExecRunner struct{}

// Run executes cmd with args, feeding stdin to its standard input, and
// returns the captured stdout/stderr.
func (ExecRunner) Run(ctx context.Context, cmd string, args []string, stdin string) (string, string, error) {
	c := exec.CommandContext(ctx, cmd, args...) //nolint:gosec // cmd/args derived from validated config and stable constants
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	return stdout.String(), stderr.String(), err
}
