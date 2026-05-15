package firewall_test

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rdoorn/safe/internal/firewall"
	"github.com/stretchr/testify/require"
)

// fakeRunner records what would have been executed.
type fakeRunner struct {
	cmd    string
	args   []string
	stdin  string
	err    error
	stderr string
}

func (f *fakeRunner) Run(_ context.Context, cmd string, args []string, stdin string) (stdout, stderr string, err error) {
	f.cmd = cmd
	f.args = args
	f.stdin = stdin
	return "", f.stderr, f.err
}

func TestApplyShellsOutToNFT(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 100,
	})

	r := &fakeRunner{}
	require.NoError(t, firewall.Apply(context.Background(), rs, firewall.ApplyOptions{
		NFTPath: "/usr/sbin/nft",
		Runner:  r,
	}))

	require.Equal(t, "/usr/sbin/nft", r.cmd)
	require.Equal(t, []string{"-f", "-"}, r.args)
	require.Contains(t, r.stdin, "table inet safe")
}

func TestApplyDefaultNFTPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nft path detection only matters on Linux")
	}
	// Construct, don't run — we just want to confirm a sensible default
	// without invoking nft.
	require.True(t, strings.HasSuffix(filepath.Base(firewall.DefaultNFTPath()), "nft"))
}

func TestApplyPropagatesErrors(t *testing.T) {
	rs := firewall.Build(firewall.Inputs{
		UpstreamDNS: []net.IP{net.ParseIP("1.1.1.1")},
		FirewallUID: 100,
	})

	r := &fakeRunner{err: context.Canceled, stderr: "Operation not permitted"}
	err := firewall.Apply(context.Background(), rs, firewall.ApplyOptions{
		NFTPath: "/usr/sbin/nft",
		Runner:  r,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Operation not permitted")
}
