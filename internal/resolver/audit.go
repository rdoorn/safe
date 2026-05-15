package resolver

import (
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

// JSONLAuditor writes one JSON object per line to a writer. Each line is
// self-contained so log shipping / grep workflows stay trivial. It is
// safe for concurrent use.
type JSONLAuditor struct {
	mu     sync.Mutex
	w      io.Writer
	nowFn  func() time.Time
	encErr error
}

// NewJSONLAuditor returns an auditor that writes to w. A nil writer is
// accepted; the auditor becomes a no-op (useful in tests).
func NewJSONLAuditor(w io.Writer) *JSONLAuditor {
	return &JSONLAuditor{w: w, nowFn: time.Now}
}

type auditLine struct {
	TS    string   `json:"ts"`
	Event string   `json:"event"`
	FQDN  string   `json:"fqdn"`
	Addr  string   `json:"addr,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	TTL   string   `json:"ttl,omitempty"`
}

// Allow records a successful allowlist match.
func (a *JSONLAuditor) Allow(name string, clientAddr net.Addr, ips []net.IP, ttl time.Duration) {
	ipStrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	a.write(auditLine{
		TS:    a.nowFn().UTC().Format(time.RFC3339Nano),
		Event: "allow",
		FQDN:  name,
		Addr:  addrString(clientAddr),
		IPs:   ipStrs,
		TTL:   ttl.String(),
	})
}

// Deny records a rejected query.
func (a *JSONLAuditor) Deny(name string, clientAddr net.Addr) {
	a.write(auditLine{
		TS:    a.nowFn().UTC().Format(time.RFC3339Nano),
		Event: "deny",
		FQDN:  name,
		Addr:  addrString(clientAddr),
	})
}

func (a *JSONLAuditor) write(line auditLine) {
	if a == nil || a.w == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := json.NewEncoder(a.w).Encode(line); err != nil {
		a.encErr = err
	}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
