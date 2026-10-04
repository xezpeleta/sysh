// journal.go — parse `journalctl -t sysh -o json` lines into Events.
package watch

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// journalLine is the subset of journal fields sysh writes
// (internal/audit). journalctl emits every value as a string; absent
// fields are absent keys.
type journalLine struct {
	Realtime string `json:"__REALTIME_TIMESTAMP"` // µs since epoch
	Hostname string `json:"_HOSTNAME"`
	UID      string `json:"_UID"`

	Decision string `json:"DECISION"`
	KeyID    string `json:"KEYID"`
	Argv     string `json:"ARGV"` // JSON array of strings
	Rule     string `json:"RULE"`
	Exit     string `json:"EXIT"`
	DurMS    string `json:"DURATION_MS"`
	Priv     string `json:"PRIV"`
	Phase    string `json:"PHASE"`
	Detail   string `json:"DETAIL"`
}

// parseEventLine decodes one journalctl JSON line into an Event for
// the given host name (the config name, not _HOSTNAME, so filters and
// approve commands match what the operator typed).
func parseEventLine(host, line string) (Event, error) {
	var jl journalLine
	if err := json.Unmarshal([]byte(line), &jl); err != nil {
		return Event{}, fmt.Errorf("bad journal line: %v", err)
	}
	if jl.Decision == "" {
		return Event{}, fmt.Errorf("journal line without DECISION (not sysh?)")
	}

	ev := Event{
		Host:     host,
		Decision: jl.Decision,
		Key:      jl.KeyID,
		Priv:     jl.Priv == "true",
		Phase:    jl.Phase,
		Detail:   jl.Detail,
	}
	if jl.Argv != "" {
		_ = json.Unmarshal([]byte(jl.Argv), &ev.Argv) // best effort; nil on error
	}
	if us, err := strconv.ParseInt(jl.Realtime, 10, 64); err == nil && us > 0 {
		ev.TS = time.UnixMicro(us).UTC().Format(time.RFC3339)
	}
	if jl.Rule != "" {
		if n, err := strconv.Atoi(jl.Rule); err == nil {
			ev.Rule = &n
		}
	}
	if jl.Exit != "" {
		if n, err := strconv.Atoi(jl.Exit); err == nil {
			ev.Exit = &n
		}
	}
	if jl.DurMS != "" {
		if n, err := strconv.ParseInt(jl.DurMS, 10, 64); err == nil {
			ev.DurMS = &n
		}
	}
	if jl.UID != "" {
		if n, err := strconv.Atoi(jl.UID); err == nil {
			ev.UID = n
		}
	}
	return ev, nil
}
