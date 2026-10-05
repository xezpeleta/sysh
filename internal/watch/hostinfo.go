// hostinfo.go — the periodic per-host policy summary behind the
// hosts view: one read-only exec over the operator's root SSH
// channel (`sysh policy show --json`), the same transport the
// journal tail and the approvals poller use. Hosts running an
// older sysh without `show` answer with an error — the view then
// omits the policy block. No new state on the host, no power in
// the browser.
package watch

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os/exec"
	"time"
)

// HostPolicy mirrors `sysh policy show --json`.
type HostPolicy struct {
	Mode             string    `json:"mode"`
	Rules            int       `json:"rules"`
	Allow            int       `json:"allow"`
	Deny             int       `json:"deny"`
	Approval         int       `json:"approval"`
	Privileged       int       `json:"privileged"`
	AgentScripts     string    `json:"agent_scripts"`
	AgentScriptsMode string    `json:"agent_scripts_mode"`
	SHA256           string    `json:"sha256"`
	MTime            string    `json:"mtime"`
	FetchedAt        time.Time `json:"fetched_at"`
}

// HostInfoPoller asks every host for its policy summary every
// interval. All fields but Addrs are optional (seams for tests).
type HostInfoPoller struct {
	Addrs     map[string]string // host name → ssh address
	Every     time.Duration     // default 2m
	SSHRun    func(addr string, argv []string) ([]byte, error)
	Put       func(host string, p *HostPolicy) // store (nil = drop)
	HostState func(name string) string         // skip down hosts
	Log       *log.Logger
}

// realSSHRun execs argv on root@addr and returns stdout.
func realSSHRun(addr string, argv []string) ([]byte, error) {
	cmd := exec.Command("ssh", append(sshDestArgs(addr), argv...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// fetch asks one host. nil means "no answer" (down, old sysh, bad
// json) — the caller keeps whatever it had, or nothing.
func (h *HostInfoPoller) fetch(addr string) *HostPolicy {
	run := h.SSHRun
	if run == nil {
		run = realSSHRun
	}
	out, err := run(addr, []string{"sysh", "policy", "show", "--json"})
	if err != nil {
		if h.Log != nil {
			h.Log.Printf("hostinfo %s: no answer: %v", addr, err)
		}
		return nil
	}
	var p HostPolicy
	if json.Unmarshal(out, &p) != nil || p.Mode == "" {
		if h.Log != nil {
			h.Log.Printf("hostinfo %s: unparseable answer: %q", addr, out)
		}
		return nil
	}
	p.FetchedAt = time.Now()
	return &p
}

// pollOnce asks every host once (skipping reconnecting ones — a
// down host must never cost the viewer more than its ConnectTimeout).
func (h *HostInfoPoller) pollOnce() {
	for name, addr := range h.Addrs {
		if h.HostState != nil && h.HostState(name) == "reconnecting" {
			continue
		}
		p := h.fetch(addr)
		if h.Put != nil {
			h.Put(name, p)
		}
	}
}

// Run waits for the followers to settle, polls once, then keeps
// polling on the ticker. The settle delay matters: at startup every
// follower is briefly "reconnecting" while its journalctl connects,
// and a first poll in that window would skip the whole fleet and
// leave the hosts view dark for a full interval.
func (h *HostInfoPoller) Run() {
	every := h.Every
	if every <= 0 {
		every = 2 * time.Minute
	}
	time.Sleep(10 * time.Second)
	h.pollOnce()
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		h.pollOnce()
	}
}
