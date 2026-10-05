// hub.go — the in-memory aggregator: a ring buffer of recent events,
// a fan-out to live subscribers, and per-host connection status.
package watch

import (
	"sync"
	"time"
)

// HostStatus is one followed host's connection state.
type HostStatus struct {
	Name       string       `json:"name"`
	State      string       `json:"state"` // "following" | "reconnecting" | "idle"
	LastEvent  time.Time    `json:"last_event"`
	LastError  string       `json:"last_error"`
	Since      time.Time    `json:"since"` // when the follower (re)connected
	EventsSeen int64        `json:"events_seen"`

	// Policy is the last `sysh policy show` answer (hostinfo.go),
	// nil when the host has not answered yet (or runs an older sysh
	// without the subcommand).
	Policy *HostPolicy `json:"policy,omitempty"`
}

// Hub is safe for concurrent use.
type Hub struct {
	mu    sync.Mutex
	ring  []Event // circular, oldest overwritten
	next  uint64  // sequence numbers
	subs  map[chan Event]struct{}
	hosts map[string]*HostStatus
}

// NewHub returns a hub with a ring of the given capacity.
func NewHub(capacity int) *Hub {
	if capacity < 1 {
		capacity = 1
	}
	return &Hub{
		ring:  make([]Event, 0, capacity),
		subs:  make(map[chan Event]struct{}),
		hosts: make(map[string]*HostStatus),
	}
}

// Add appends an event (assigning its sequence number) and fans it out
// to every subscriber. Slow subscribers drop events rather than block
// the followers (their channels are buffered; the send is non-blocking).
func (h *Hub) Add(ev Event) Event {
	h.mu.Lock()
	h.next++
	ev.Seq = h.next
	if len(h.ring) < cap(h.ring) {
		h.ring = append(h.ring, ev)
	} else {
		copy(h.ring, h.ring[1:]) // slide left, oldest falls off
		h.ring[len(h.ring)-1] = ev
	}
	if st := h.hosts[ev.Host]; st != nil {
		st.EventsSeen++
		st.LastEvent = time.Now()
	}
	subs := make([]chan Event, 0, len(h.subs))
	for ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default: // drop for slow consumer
		}
	}
	return ev
}

// Snapshot returns up to n most recent events, oldest first.
func (h *Hub) Snapshot(n int) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > len(h.ring) || n < 0 {
		n = len(h.ring)
	}
	out := make([]Event, n)
	copy(out, h.ring[len(h.ring)-n:])
	return out
}

// Subscribe registers a buffered live channel. The returned cancel
// function must be called when the consumer goes away.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// SetHost upserts a host's status.
func (h *Hub) SetHost(name, state, lastErr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.hosts[name]
	if !ok {
		st = &HostStatus{Name: name}
		h.hosts[name] = st
	}
	st.State = state
	st.LastError = lastErr
	if state == "following" {
		st.Since = time.Now()
	}
}

// SetHostPolicy upserts a host's policy summary (hostinfo.go).
func (h *Hub) SetHostPolicy(name string, p *HostPolicy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.hosts[name]
	if !ok {
		st = &HostStatus{Name: name}
		h.hosts[name] = st
	}
	st.Policy = p
}

// Hosts returns the status list.
func (h *Hub) Hosts() []HostStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostStatus, 0, len(h.hosts))
	for _, st := range h.hosts {
		out = append(out, *st)
	}
	return out
}
