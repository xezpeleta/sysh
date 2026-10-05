// approvals.go — poll each host's pending approval requests (root
// channel, `sysh approvals --json`). The viewer never answers them; it
// shows what waits and how to answer it where the ceremony lives.
package watch

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
)

// Pending is one request waiting for an operator, per `sysh approvals`.
type Pending struct {
	Host         string   `json:"host"`
	ID           string   `json:"id"`
	Argv         []string `json:"argv"`
	Key          string   `json:"key"`
	AgeSec       int      `json:"age_sec"`
	Expired      bool     `json:"expired"`
	RemainingSec int      `json:"remaining_sec"` // TTL left, clamped at 0: the panel counts down to it
	Agent        *AgentInfo `json:"agent,omitempty"` // what the filing agent is doing (agents.go)
}

// fetchOneFunc lists one host's pending requests. Seam for tests; the
// production implementation shells out over the operator's root SSH.
type fetchOneFunc func(host, addr string) ([]Pending, error)

// realFetchOne runs `ssh root@addr sysh approvals --json`.
func realFetchOne(host, addr string) ([]Pending, error) {
	cmd := exec.Command("ssh", append(sshDestArgs(addr), "sysh", "approvals", "--json")...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %v", host, err)
	}
	return parseApprovals(host, out)
}

// parseApprovals decodes `sysh approvals --json` output for a host.
// The "no pending requests" case prints plain text, not JSON.
func parseApprovals(host string, body []byte) ([]Pending, error) {
	s := strings.TrimSpace(string(body))
	if s == "" || s == "no pending requests" {
		return nil, nil
	}
	var rows []struct {
		ID      string   `json:"id"`
		Argv    []string `json:"argv"`
		Key     string   `json:"key"`
		AgeSec  int      `json:"age_sec"`
		Expired bool     `json:"expired"`
	}
	if err := json.Unmarshal([]byte(s), &rows); err != nil {
		return nil, fmt.Errorf("approvals: %v", err)
	}
	ttl := int(approval.RequestTTL.Seconds())
	out := make([]Pending, 0, len(rows))
	for _, r := range rows {
		left := ttl - r.AgeSec
		if left < 0 {
			left = 0
		}
		out = append(out, Pending{Host: host, ID: r.ID, Argv: r.Argv, Key: r.Key, AgeSec: r.AgeSec, Expired: r.Expired, RemainingSec: left})
	}
	return out, nil
}

// ApprovalPoller polls every host periodically into a snapshot the
// HTTP layer serves, so the UI's pending panel stays consistent
// across hosts.
type ApprovalPoller struct {
	hosts   []hostEntry
	fetchOne fetchOneFunc
	every   time.Duration

	// HostState reports a follower's connection state ("following",
	// "reconnecting", …); nil = poll everything. A host the follower
	// cannot reach gets skipped instead of stalling the cycle on its
	// ConnectTimeout — one down host must not delay every other
	// host's pending panel.
	HostState func(name string) string

	mu     sync.Mutex
	latest []Pending

	stopCh chan struct{}
	once   sync.Once
}

type hostEntry struct {
	name string
	addr string
}

// NewApprovalPoller wires a poller for the given host→addr map.
func NewApprovalPoller(hosts map[string]string, every time.Duration, fetchOne fetchOneFunc) *ApprovalPoller {
	if fetchOne == nil {
		fetchOne = realFetchOne
	}
	entries := make([]hostEntry, 0, len(hosts))
	for name, addr := range hosts {
		entries = append(entries, hostEntry{name, addr})
	}
	return &ApprovalPoller{
		hosts:   entries,
		fetchOne: fetchOne,
		every:   every,
		stopCh:  make(chan struct{}),
	}
}

// Run polls until Stop. A failed host leaves its previous rows out;
// errors never clear the panel silently to stale data — a failed fetch
// is simply not represented until it succeeds again.
func (p *ApprovalPoller) Run() {
	for {
		p.poll()
		select {
		case <-p.stopCh:
			return
		case <-time.After(p.every):
		}
	}
}

// poll fetches all hosts sequentially (one root SSH each; a handful of
// hosts keeps this well under the interval).
func (p *ApprovalPoller) poll() {
	var all []Pending
	for _, h := range p.hosts {
		if p.HostState != nil && p.HostState(h.name) == "reconnecting" {
			continue // down: its rows are stale by definition
		}
		rows, err := p.fetchOne(h.name, h.addr)
		if err != nil {
			continue
		}
		all = append(all, rows...)
	}
	p.mu.Lock()
	p.latest = all
	p.mu.Unlock()
}

// Snapshot returns the latest pending rows.
func (p *ApprovalPoller) Snapshot() []Pending {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Pending, len(p.latest))
	copy(out, p.latest)
	return out
}

// Stop ends the poll loop.
func (p *ApprovalPoller) Stop() {
	p.once.Do(func() { close(p.stopCh) })
}
