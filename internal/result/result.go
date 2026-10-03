// Package result implements the §6.4 result contract: every terminal
// outcome of the gateway writes exactly one structured JSON line to
// stderr. This line — not the process exit code — is the authoritative
// machine-readable contract (exit codes collide with child statuses).
package result

import (
	"encoding/json"
	"io"
)

// Marker distinguishing a gateway line from child output on stderr.
const SyshMarker = 1

// Outcome classes.
const (
	ClassExec        = "exec"                   // a child ran to completion
	ClassTimeout     = "timeout"                // child killed on timeout (exit 124)
	ClassTruncated   = "output_truncated"       // child killed on output cap (exit 124)
	ClassDenied      = "denied"                 // policy refusal (exit 125)
	ClassMalformed   = "malformed"              // non-printable/bad argv (exit 3)
	ClassLockdown    = "lockdown"               // tripwire present (exit 2)
	ClassPrivileged  = "privileged_unavailable" // phase-2 rule on a phase-1 build (exit 126)
	ClassSessionDrop = "session_drop"           // ssh session ended, child killed
	ClassBuiltin     = "builtin"                // sy-docs / sy-policy served
	ClassInternal    = "internal_error"         // unexpected failure, fail closed
	ClassNoInput     = "no_input"               // interactive login attempt refused
)

// Exit codes (human convenience; the stderr line is authoritative).
const (
	ExitLockdown    = 2
	ExitMalformed   = 3
	ExitApproval    = 30 // phase 2: approval required
	ExitTimeout     = 124
	ExitDenied      = 125
	ExitPrivileged  = 126 // privileged unavailable pre-phase-2
	ExitSessionDrop = 128 // + signal number
)

// Line is the JSON structure written to stderr.
type Line struct {
	Sysh      int    `json:"sysh"`  // always 1; marks this as a gateway line
	Class     string `json:"class"` // outcome class (see Class* constants)
	Detail    string `json:"detail,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Rule      *int   `json:"rule,omitempty"` // matching rule index, if any
	Exit      *int   `json:"exit,omitempty"` // child exit status, if a child ran
	Truncated bool   `json:"truncated,omitempty"`
	Scope     bool   `json:"scope,omitempty"` // ran inside a systemd scope
	Unit      string `json:"unit,omitempty"`  // systemd scope unit name
	RequestID string `json:"request_id,omitempty"`
}

// Format renders the line as a single JSON document plus newline.
func (l Line) Format() ([]byte, error) {
	l.Sysh = SyshMarker
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Write emits the line to w.
func (l Line) Write(w io.Writer) error {
	b, err := l.Format()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// FromError formats and writes a refusal line in one step.
func Write(w io.Writer, class, detail, keyID string, exit int) {
	_ = Line{Class: class, Detail: detail, KeyID: keyID}.withExit(exit).Write(w)
}

func (l Line) withExit(exit int) Line { l.Exit = &exit; return l }

// Human helper for fatal internal errors.
func Internal(w io.Writer, detail string) {
	Write(w, ClassInternal, detail, "", ExitDenied)
}
