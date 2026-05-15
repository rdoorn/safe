package keyholder

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Bootstrap reads exactly one line from r, trims surrounding whitespace,
// and returns it as a Key. The reader can be closed by the caller as
// soon as Bootstrap returns — the key lives only in memory.
//
// Bootstrap rejects empty or whitespace-only input so a silently-broken
// pipe doesn't leave the keyholder authenticating with an empty string.
func Bootstrap(r io.Reader) (*Key, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read key: %w", err)
	}
	v := strings.TrimSpace(line)
	if v == "" {
		return nil, errors.New("key is empty")
	}
	return NewKey(v), nil
}
