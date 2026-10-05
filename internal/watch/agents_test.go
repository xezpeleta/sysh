package watch

import (
	"testing"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
)

func agentEvent(decision string, argv []string, key, detail, ts string) Event {
	return Event{
		Host:     "h1",
		TS:       ts,
		Decision: decision,
		Key:      key,
		Argv:     argv,
		Detail:   detail,
	}
}

func TestAgentsLifecycle(t *testing.T) {
	a := NewAgents()
	key := "sy/agent"
	argv := []string{"/usr/bin/uptime"}
	id := approval.ID(argv, key)
	ts := time.Now().UTC().Format(time.RFC3339)

	// Agent files; no poll yet.
	a.Observe(agentEvent(audit.DecisionRequest, argv, key, "privileged rule requires operator approval", ts))
	if rows := a.Recent(10); len(rows) != 1 || rows[0].State != AgentFiled {
		t.Fatalf("after file: %+v", rows)
	}

	// Agent polls; classification says pending.
	a.Observe(agentEvent(audit.DecisionResult, []string{"sysh-result", id}, key,
		"no result for "+id+" yet — the request is pending operator approval; wait and re-check", ts))
	rows := a.Recent(10)
	if rows[0].State != AgentWaiting || rows[0].Polls != 1 {
		t.Fatalf("after pending poll: %+v", rows)
	}

	// Operator approves (root side; same argv+key → same id).
	a.Observe(agentEvent(audit.DecisionApprove, argv, key, "operator approved", ts))
	rows = a.Recent(10)
	if rows[0].State != AgentApproved || rows[0].Polls != 1 {
		t.Fatalf("after approve: %+v", rows)
	}

	// Agent polls again; served.
	exit := 0
	served := agentEvent(audit.DecisionResult, []string{"sysh-result", id}, key, "exit=0", ts)
	served.Exit = &exit
	a.Observe(served)
	rows = a.Recent(10)
	if rows[0].State != AgentFetched || rows[0].Exit == nil || *rows[0].Exit != 0 {
		t.Fatalf("after fetch: %+v", rows)
	}

	// Augment fills the pending row.
	pend := []Pending{{Host: "h1", ID: id}}
	a.augment(pend)
	if pend[0].Agent == nil || pend[0].Agent.State != AgentFetched || pend[0].Agent.Polls != 2 {
		t.Fatalf("augment: %+v", pend[0].Agent)
	}

	// Expiry teaching folds in too: re-file resets the lifecycle.
	a.Observe(agentEvent(audit.DecisionResult, []string{"sysh-result", id}, key,
		"request "+id+" expired — no operator answer within 10m0s (refuse-by-default); re-run the command to file a fresh request", ts))
	if rows := a.Recent(10); rows[0].State != AgentExpired {
		t.Fatalf("after expiry poll: %+v", rows)
	}
	a.Observe(agentEvent(audit.DecisionRequest, argv, key, "privileged rule requires operator approval", ts))
	if rows := a.Recent(10); rows[0].State != AgentFiled {
		t.Fatalf("after re-file: %+v", rows)
	}

	// Re-file after an approval (deterministic ids recycle: a retry
	// after the approve-side exec consumed the single use) starts a
	// new life too — the approval belongs to the previous request.
	a.Observe(agentEvent(audit.DecisionApprove, argv, key, "operator approved", ts))
	if rows := a.Recent(10); rows[0].State != AgentApproved {
		t.Fatalf("after approve (2): %+v", rows)
	}
	a.Observe(agentEvent(audit.DecisionRequest, argv, key, "privileged rule requires operator approval", ts))
	if rows := a.Recent(10); rows[0].State != AgentFiled {
		t.Fatalf("after re-file post-approval: %+v", rows)
	}
}

func TestAgentsNilSafe(t *testing.T) {
	var a *Agents
	a.Observe(Event{Decision: audit.DecisionRequest})
	a.augment(nil)
	if rows := a.Recent(5); rows != nil {
		t.Fatalf("nil agents must be inert")
	}
}

func TestAgentsBadResultUsage(t *testing.T) {
	a := NewAgents()
	// usage error: argv[1] is not a valid id — must be ignored
	a.Observe(agentEvent(audit.DecisionResult, []string{"sysh-result", "req_short"}, "sy/a", "usage: sysh-result <request-id>", time.Now().UTC().Format(time.RFC3339)))
	if rows := a.Recent(10); len(rows) != 0 {
		t.Fatalf("bad usage must not create an entry: %+v", rows)
	}
}
