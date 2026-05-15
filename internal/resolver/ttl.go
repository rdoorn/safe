package resolver

import "time"

// DefaultMinTTL and DefaultMaxTTL bound how long an nftables allow-rule
// stays alive after the DNS response that installed it. The minimum keeps
// CDNs that return 1s TTLs from churning the ruleset; the maximum keeps
// a single short-lived allow from outliving the session.
const (
	DefaultMinTTL = 30 * time.Second
	DefaultMaxTTL = 1 * time.Hour
)

// ClampTTL returns ttl bounded to [minTTL, maxTTL]. A zero or negative
// ttl is treated as below-minimum.
func ClampTTL(ttl, minTTL, maxTTL time.Duration) time.Duration {
	if ttl < minTTL {
		return minTTL
	}
	if ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

// ClampTTLSeconds is a convenience for DNS TTLs which arrive as
// uint32 seconds.
func ClampTTLSeconds(seconds uint32, minTTL, maxTTL time.Duration) time.Duration {
	return ClampTTL(time.Duration(seconds)*time.Second, minTTL, maxTTL)
}
