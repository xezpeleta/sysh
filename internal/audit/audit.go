// Package audit implements the §8 event model and the journald sink.
// sy-side events go to journald through its native socket protocol
// (pure Go, no cgo); the journal attaches kernel-trusted _UID, _PID and
// _EXE that the sy UID cannot forge. Fail-closed semantics are enforced
// by the caller: if the pre-exec event cannot be written, the exec is
// denied.
package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
)

// Decision values.
const (
	DecisionAllow      = "allow"
	DecisionDeny       = "deny"
	DecisionLockdown   = "lockdown"
	DecisionMalformed  = "malformed"
	DecisionBuiltin    = "builtin"
	DecisionPrivileged = "privileged"
	DecisionSession    = "session_drop"
	DecisionTimeout    = "timeout"
	DecisionTruncated  = "output_truncated"
	DecisionInternal   = "internal"
)

// Event is one structured exec-attempt record (§8.1).
type Event struct {
	Time        time.Time
	Decision    string
	KeyID       string
	Fingerprint string
	Rule        *int // nil = no rule matched
	Argv        []string
	Exit        int // -1 = n/a
	DurationMS  int64
	Unit        string
	Scope       bool
	PolicySHA   string
	Mode        string
	Truncated   bool
	Phase       string // "pre" (fail-closed), "post", ""
	Detail      string
}

// Sink emits events. journalSink is the production implementation;
// tests use a recorder.
type Sink interface {
	Emit(ev Event) error
}

// JournalSink writes to journald with SYSLOG_IDENTIFIER=sysh.
type JournalSink struct{}

// Emit sends one event to journald.
func (JournalSink) Emit(ev Event) error {
	msg := fmt.Sprintf("%s key=%s argv=%s", ev.Decision, ev.KeyID, quoteArgv(ev.Argv))
	if ev.Rule != nil {
		msg += fmt.Sprintf(" rule=%d", *ev.Rule)
	}
	// Outcome fields (EXIT, DURATION, SCOPE) exist only on post events;
	// pre events record intent — the fail-closed guarantee — and their
	// zero Exit/Scope must not be serialized as real values.
	if ev.Exit >= 0 && ev.Phase == "post" {
		msg += fmt.Sprintf(" exit=%d", ev.Exit)
	}
	if ev.DurationMS >= 0 && ev.Phase == "post" {
		msg += fmt.Sprintf(" (%dms)", ev.DurationMS)
	}

	priority := journal.PriInfo
	switch ev.Decision {
	case DecisionDeny, DecisionMalformed, DecisionPrivileged:
		priority = journal.PriWarning
	case DecisionLockdown, DecisionInternal:
		priority = journal.PriErr
	}

	vars := map[string]string{
		"SYSLOG_IDENTIFIER": "sysh",
		"DECISION":          ev.Decision,
		"KEYID":             orUnknown(ev.KeyID),
		"FINGERPRINT":       orUnknown(ev.Fingerprint),
		"POLICY_SHA":        orUnknown(ev.PolicySHA),
		"MODE":              orUnknown(ev.Mode),
	}
	if argv, err := json.Marshal(ev.Argv); err == nil {
		vars["ARGV"] = string(argv)
	}
	if ev.Rule != nil {
		vars["RULE"] = fmt.Sprintf("%d", *ev.Rule)
	}
	if ev.Exit >= 0 && ev.Phase == "post" {
		vars["EXIT"] = fmt.Sprintf("%d", ev.Exit)
	}
	if ev.DurationMS >= 0 && ev.Phase == "post" {
		vars["DURATION_MS"] = fmt.Sprintf("%d", ev.DurationMS)
	}
	if ev.Unit != "" {
		vars["UNIT"] = ev.Unit
	}
	if ev.Phase == "post" {
		vars["SCOPE"] = fmt.Sprintf("%t", ev.Scope)
	}
	if ev.Phase != "" {
		vars["PHASE"] = ev.Phase
	}
	if ev.Truncated {
		vars["TRUNCATED"] = "true"
	}
	if ev.Detail != "" {
		vars["DETAIL"] = ev.Detail
	}

	return journal.Send(msg, priority, vars)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func quoteArgv(argv []string) string {
	out := "["
	for i, a := range argv {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%q", a)
	}
	return out + "]"
}

// Recorder is an in-memory sink for tests.
type Recorder struct {
	Events []Event
}

// Emit records the event.
func (r *Recorder) Emit(ev Event) error {
	r.Events = append(r.Events, ev)
	return nil
}
