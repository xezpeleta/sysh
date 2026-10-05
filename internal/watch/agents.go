// agents.go — correlate journal events per request id so the watch
// can answer the operator's two live questions: is the agent still
// waiting for me? did it get the answer? Everything needed is already
// in the journal (the file event, the approve events, every
// sysh-result poll and its classification); this just keeps the last
// state per request. Read-only, derived, and rebuilt from journal
// history on every watch start — the journal stays the source of
// truth (§9).
package watch

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
)

// Agent states, one per request id.
const (
	AgentFiled    = "filed"    // agent filed; no poll seen yet
	AgentWaiting  = "waiting"  // last poll answered "pending approval"
	AgentExpired  = "expired"  // last poll answered "expired" (agent should re-file)
	AgentApproved = "approved" // operator answered; agent has not polled since
	AgentFetched  = "fetched"  // agent got the result (sysh-result served)
)

// AgentInfo is the per-request agent state merged into pending rows.
type AgentInfo struct {
	State  string `json:"state"`
	Polls  int    `json:"polls"`
	AgoSec int    `json:"ago_sec"` // seconds since last poll; 0 = never polled
}

// AgentRow is one tracked request as listed by /api/agents.
type AgentRow struct {
	Host           string   `json:"host"`
	ID             string   `json:"id"`
	Key            string   `json:"key"`
	Argv           []string `json:"argv"`
	State          string   `json:"state"`
	Polls          int      `json:"polls"`
	FiledAgoSec    int      `json:"filed_ago_sec"`
	LastPollAgoSec int      `json:"last_poll_ago_sec"` // 0 = never
	ApprovedAgoSec int      `json:"approved_ago_sec"`  // 0 = never
	Exit           *int     `json:"exit,omitempty"`
}

type agentEntry struct {
	host       string
	id         string
	key        string
	argv       []string
	state      string
	polls      int
	filedAt    time.Time
	lastPoll   time.Time
	approvedAt time.Time
	exit       *int
}

// Agents is the correlation table. Nil-receiver safe: followers and
// tests without it are fine.
type Agents struct {
	mu      sync.Mutex
	entries map[string]*agentEntry // host + "/" + id
}

// NewAgents returns an empty tracker.
func NewAgents() *Agents {
	return &Agents{entries: map[string]*agentEntry{}}
}

// Observe folds one journal event into the table. Ids are derived
// exactly as the gateway derives them (argv + key), so request,
// approve, and result events meet in the same row.
func (a *Agents) Observe(ev Event) {
	if a == nil {
		return
	}
	var id string
	switch ev.Decision {
	case audit.DecisionRequest:
		if len(ev.Argv) == 0 || ev.Key == "" {
			return
		}
		id = approval.ID(ev.Argv, ev.Key)
	case audit.DecisionApprove:
		if len(ev.Argv) == 0 || ev.Key == "" {
			return
		}
		id = approval.ID(ev.Argv, ev.Key)
	case audit.DecisionResult:
		if len(ev.Argv) < 2 || !approval.ValidID(ev.Argv[1]) {
			return
		}
		id = ev.Argv[1]
	default:
		return
	}
	if !approval.ValidID(id) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	k := ev.Host + "/" + id
	e := a.entries[k]
	if e == nil {
		e = &agentEntry{host: ev.Host, id: id}
		a.entries[k] = e
	}
	at := ev.at()
	if at.IsZero() {
		at = time.Now()
	}

	switch ev.Decision {
	case audit.DecisionRequest:
		e.key, e.argv = ev.Key, ev.Argv
		e.filedAt = at
		// A re-file (renewal, or after expiry) means the agent is at
		// it again; the fetch — or the approval — that may have come
		// before belongs to the previous life of the same id.
		if e.state == "" || e.state == AgentExpired || e.state == AgentFetched || e.state == AgentApproved {
			e.state = AgentFiled
			e.exit = nil
			e.polls = 0
			e.lastPoll = time.Time{}
			e.approvedAt = time.Time{}
		}
	case audit.DecisionApprove:
		e.approvedAt = at
		if e.state != AgentFetched {
			e.state = AgentApproved
		}
	case audit.DecisionResult:
		e.polls++
		e.lastPoll = at
		d := ev.Detail
		switch {
		case strings.Contains(d, "pending operator approval"):
			e.state = AgentWaiting
		case strings.Contains(d, "expired"):
			e.state = AgentExpired
		case strings.HasPrefix(d, "exit="):
			e.state = AgentFetched
			e.exit = ev.Exit
			// The result event carries the exit in its detail text;
			// the structured EXIT field is not always present.
			if e.exit == nil {
				if n, err := strconv.Atoi(strings.TrimPrefix(d, "exit=")); err == nil {
					e.exit = &n
				}
			}
		}
	}
	a.pruneLocked()
}

// pruneLocked bounds the table; called with the lock held.
func (a *Agents) pruneLocked() {
	if len(a.entries) <= 300 {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	ks := make([]kv, 0, len(a.entries))
	for k, e := range a.entries {
		t := e.filedAt
		for _, x := range []time.Time{e.lastPoll, e.approvedAt} {
			if x.After(t) {
				t = x
			}
		}
		ks = append(ks, kv{k, t})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].t.Before(ks[j].t) })
	for _, e := range ks[:len(ks)-300] {
		delete(a.entries, e.k)
	}
}

// augment fills the Agent field of pending rows from the table.
func (a *Agents) augment(rows []Pending) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range rows {
		e := a.entries[rows[i].Host+"/"+rows[i].ID]
		if e == nil {
			continue
		}
		info := AgentInfo{State: e.state, Polls: e.polls}
		if !e.lastPoll.IsZero() {
			info.AgoSec = maxInt(0, int(time.Since(e.lastPoll).Seconds()))
		}
		rows[i].Agent = &info
	}
}

// Recent lists tracked requests, newest first, at most n.
func (a *Agents) Recent(n int) []AgentRow {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AgentRow, 0, len(a.entries))
	for _, e := range a.entries {
		r := AgentRow{
			Host: e.host, ID: e.id, Key: e.key, Argv: e.argv,
			State: e.state, Polls: e.polls,
		}
		if !e.filedAt.IsZero() {
			r.FiledAgoSec = maxInt(0, int(time.Since(e.filedAt).Seconds()))
		}
		if !e.lastPoll.IsZero() {
			r.LastPollAgoSec = maxInt(0, int(time.Since(e.lastPoll).Seconds()))
		}
		if !e.approvedAt.IsZero() {
			r.ApprovedAgoSec = maxInt(0, int(time.Since(e.approvedAt).Seconds()))
		}
		r.Exit = e.exit
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].FiledAgoSec, out[j].FiledAgoSec
		return ti < tj // smaller ago = newer
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
