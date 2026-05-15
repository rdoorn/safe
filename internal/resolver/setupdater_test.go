package resolver_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rdoorn/safe/internal/resolver"
	"github.com/stretchr/testify/require"
)

type recordingRunner struct {
	cmd    string
	args   []string
	stdin  string
	err    error
	stderr string
}

func (r *recordingRunner) Run(_ context.Context, cmd string, args []string, stdin string) (stdout, stderr string, err error) {
	r.cmd = cmd
	r.args = args
	r.stdin = stdin
	return "", r.stderr, r.err
}

func TestSetUpdaterAddIPv4(t *testing.T) {
	r := &recordingRunner{}
	u := &resolver.SetUpdater{NFTPath: "/usr/sbin/nft", Runner: r}

	require.NoError(t, u.Add(context.Background(), net.ParseIP("1.2.3.4"), 60*time.Second))

	require.Equal(t, "/usr/sbin/nft", r.cmd)
	require.Equal(t, []string{"-f", "-"}, r.args)
	require.Contains(t, r.stdin, "add element inet safe allowed_v4")
	require.Contains(t, r.stdin, "1.2.3.4 timeout 60s")
}

func TestSetUpdaterAddIPv6(t *testing.T) {
	r := &recordingRunner{}
	u := &resolver.SetUpdater{NFTPath: "/usr/sbin/nft", Runner: r}

	require.NoError(t, u.Add(context.Background(), net.ParseIP("2001:db8::1"), 5*time.Minute))

	require.Contains(t, r.stdin, "add element inet safe allowed_v6")
	require.Contains(t, r.stdin, "2001:db8::1 timeout 300s")
}

func TestSetUpdaterPropagatesError(t *testing.T) {
	r := &recordingRunner{err: errors.New("boom"), stderr: "Permission denied"}
	u := &resolver.SetUpdater{NFTPath: "/usr/sbin/nft", Runner: r}

	err := u.Add(context.Background(), net.ParseIP("1.2.3.4"), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permission denied")
}

func TestSetUpdaterBatchAdd(t *testing.T) {
	r := &recordingRunner{}
	u := &resolver.SetUpdater{NFTPath: "/usr/sbin/nft", Runner: r}

	ips := []net.IP{
		net.ParseIP("1.2.3.4"),
		net.ParseIP("5.6.7.8"),
		net.ParseIP("2001:db8::1"),
	}
	require.NoError(t, u.AddMany(context.Background(), ips, 60*time.Second))

	// Single script combining all elements, so the kernel handles them
	// atomically rather than three separate calls.
	require.Contains(t, r.stdin, "1.2.3.4")
	require.Contains(t, r.stdin, "5.6.7.8")
	require.Contains(t, r.stdin, "2001:db8::1")
}

func TestSetUpdaterInvalidIP(t *testing.T) {
	u := &resolver.SetUpdater{NFTPath: "/usr/sbin/nft", Runner: &recordingRunner{}}
	err := u.Add(context.Background(), nil, time.Minute)
	require.Error(t, err)
}
