package audit

import (
	"os"
	"testing"
	"time"
)

// TestJournalSinkLive emits one event to the real journald socket.
// Skipped unless SYSH_JOURNAL_LIVE=1 (requires a local journald and
// journalctl to verify).
func TestJournalSinkLive(t *testing.T) {
	if os.Getenv("SYSH_JOURNAL_LIVE") == "" {
		t.Skip("set SYSH_JOURNAL_LIVE=1 to emit to the real journald")
	}
	sink := JournalSink{}
	err := sink.Emit(Event{
		Time:       time.Now(),
		Decision:   DecisionAllow,
		KeyID:      "smoke-test/agent",
		Argv:       []string{"/bin/echo", "hello"},
		Exit:       0,
		DurationMS: 12,
		PolicySHA:  "deadbeef",
		Mode:       "enforcing",
		Phase:      "post",
		Scope:      false,
	})
	if err != nil {
		t.Fatalf("journald emit failed: %v", err)
	}
}
