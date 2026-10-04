// Package watch implements `sy watch`: a read-only, localhost web
// viewer of what agents are doing across every sysh-managed host.
//
// Design (PROJECT.md §9): no new server-side component exists or is
// needed. Each configured host is followed over the operator's root
// SSH channel (the same transport `sy approve` uses) running
// `journalctl -t sysh -o json -f`; the journal remains the only source
// of truth, kernel-attested as always. `sy watch` aggregates, buffers,
// and renders. It holds no control power of any kind: the browser can
// look, never act. Approvals stay in the `sy approve` ceremony.
package watch

import "time"

// Event is one normalized journal entry as sent to the browser.
// Rule/Exit/Dur are nil when the source entry did not carry them
// (pre-exec entries record intent, not outcomes).
type Event struct {
	Seq      uint64   `json:"seq"`
	Host     string   `json:"host"`
	TS       string   `json:"ts"` // RFC3339
	Decision string   `json:"decision"`
	Key      string   `json:"key"`
	Argv     []string `json:"argv"`
	Rule     *int     `json:"rule"`
	Exit     *int     `json:"exit"`
	DurMS    *int64   `json:"dur_ms"`
	Priv     bool     `json:"priv"`
	Phase    string   `json:"phase"`
	Detail   string   `json:"detail"`
	UID      int      `json:"uid"`
}

// at returns the event time.
func (e Event) at() time.Time {
	t, err := time.Parse(time.RFC3339, e.TS)
	if err != nil {
		return time.Time{}
	}
	return t
}
