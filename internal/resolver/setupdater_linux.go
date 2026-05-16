//go:build linux

package resolver

import (
	"fmt"

	"github.com/google/nftables"
)

func (u *SetUpdater) applyToKernel(batch ipBatch) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open netlink: %w", err)
	}
	defer func() { _ = c.CloseLasting() }()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: u.TableName}

	if len(batch.v4) > 0 {
		setV4, err := c.GetSetByName(table, u.SetNameV4)
		if err != nil {
			return fmt.Errorf("get set %s: %w", u.SetNameV4, err)
		}
		elements := make([]nftables.SetElement, 0, len(batch.v4))
		for _, ip := range batch.v4 {
			elements = append(elements, nftables.SetElement{
				Key:     []byte(ip),
				Timeout: batch.ttl,
			})
		}
		if err := c.SetAddElements(setV4, elements); err != nil {
			return fmt.Errorf("set add v4: %w", err)
		}
	}

	if len(batch.v6) > 0 {
		setV6, err := c.GetSetByName(table, u.SetNameV6)
		if err != nil {
			return fmt.Errorf("get set %s: %w", u.SetNameV6, err)
		}
		elements := make([]nftables.SetElement, 0, len(batch.v6))
		for _, ip := range batch.v6 {
			elements = append(elements, nftables.SetElement{
				Key:     []byte(ip),
				Timeout: batch.ttl,
			})
		}
		if err := c.SetAddElements(setV6, elements); err != nil {
			return fmt.Errorf("set add v6: %w", err)
		}
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("netlink flush: %w", err)
	}
	return nil
}
