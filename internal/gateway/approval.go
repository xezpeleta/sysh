package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/policy"
	"github.com/xezpeleta/sysh/internal/result"
)

// requestApproval implements the §9 gateway half of the approval
// channel: a privileged rule carrying approval = true does not execute
// here. The gateway parks a request file in the drop box, tells the
// agent the request id, and exits 30. The root-side approver
// (sysh approve) re-checks the argv against this same policy and runs
// it; the agent picks the outcome up with sysh-result.
//
// The gateway never elevates for approval rules — it only writes a
// file it is allowed to write — so NoNewPrivs stays on.
func requestApproval(cfg Config, emit func(audit.Event) error, ident Identity,
	argv []string, dec policy.Decision, base audit.Event) int {

	id := approval.ID(argv, ident.KeyID)

	// The request event is the record (fail closed: no record, no
	// request). Key/fingerprint come from the gateway's own identity
	// read, not from the request body.
	ev := withDec(base, audit.DecisionRequest)
	ev.Detail = "privileged rule requires operator approval"
	ev.Privileged = true
	if err := emit(ev); err != nil {
		return denyResult(cfg, emit, withDec(base, audit.DecisionInternal),
			result.ClassInternal, "audit sink unavailable (fail closed): "+err.Error())
	}

	if err := writeRequest(cfg, id, ident, argv); err != nil {
		return denyResult(cfg, emit, withDec(base, audit.DecisionInternal),
			result.ClassInternal, "cannot write approval request: "+err.Error())
	}

	_ = result.Line{
		Class:     result.ClassRequest,
		KeyID:     ident.KeyID,
		Detail:    "operator approval required (sysh approvals as root on this host)",
		RequestID: id,
		Exit:      intPtr(result.ExitApproval),
	}.Write(cfg.Stderr)
	return result.ExitApproval
}

// writeRequest drops the request file into the drop box. Identical
// live requests dedupe: the id is derived from argv+key, so a repeated
// attempt renews the existing file's timestamp instead of piling up
// spool entries (§9.3).
func writeRequest(cfg Config, id string, ident Identity, argv []string) error {
	dir := cfg.RequestsDir
	if dir == "" {
		dir = approval.RequestsDir
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("approval drop box %s missing (reinstall the sysh package)", dir)
	}
	req := approval.Request{
		ID:          id,
		KeyID:       ident.KeyID,
		Fingerprint: ident.Fingerprint,
		Argv:        argv,
		Time:        cfg.Now(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(body) > approval.MaxRequestFile {
		return fmt.Errorf("request body exceeds cap")
	}
	path := approval.RequestPath(dir, id)
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if _, err := os.Stat(path); err == nil {
		// Live duplicate: renew the TTL instead of creating a second
		// entry. If the stale file is not ours to rewrite (it never is:
		// root may own the spool), the approver still re-validates
		// everything — same id, same argv, same policy check.
		flags = os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o640)
	if err != nil {
		// Another writer holds a fresh identical request — that is the
		// dedupe case; report success so the agent gets the same id.
		if os.IsExist(err) {
			_ = os.Chtimes(path, cfg.Now(), cfg.Now())
			return nil
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	return os.Chtimes(path, cfg.Now(), cfg.Now())
}

// serveResult implements the sysh-result builtin (§9): the agent
// fetches the outcome of a request it filed earlier. Read-only: the
// results directory is root-owned; a missing, expired, or tampered
// result is simply unavailable.
func serveResult(cfg Config, emit func(audit.Event) error, ident Identity, argv []string, base audit.Event) int {
	ev := withDec(base, audit.DecisionResult)
	if len(argv) != 2 || !approval.ValidID(argv[1]) {
		ev.Detail = "usage: sysh-result <request-id>"
		_ = emit(ev)
		// The format is the teaching: ids look like req_ + 12 hex
		// and arrive in an approval_required response.
		result.Write(cfg.Stderr, result.ClassNoResult, "usage: sysh-result <request-id> (id format: req_ followed by 12 hex characters; it is the request_id field of an approval_required response)", ident.KeyID, result.ExitNoResult)
		return result.ExitNoResult
	}
	id := argv[1]
	dir := cfg.ResultsDir
	if dir == "" {
		dir = approval.ResultsDir
	}

	res, err := fetchResult(dir, id, cfg.Now())
	if err != nil {
		// Say WHICH failure it is. An ambiguous "pending, expired,
		// or never approved" taught nobody: an agent that knows the
		// request expired stops waiting and re-files; the operator's
		// wall reads the same classification from the audit event.
		detail := classifyNoResult(cfg, id)
		ev.Detail = detail
		_ = emit(ev)
		result.Write(cfg.Stderr, result.ClassNoResult, detail, ident.KeyID, result.ExitNoResult)
		return result.ExitNoResult
	}

	ev.Detail = fmt.Sprintf("exit=%d", res.Exit)
	_ = emit(ev)
	if res.Stdout != "" {
		fmt.Fprint(cfg.Stdout, res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprint(cfg.Stderr, res.Stderr)
	}
	_ = result.Line{
		Class:     result.ClassResult,
		KeyID:     ident.KeyID,
		RequestID: id,
		Exit:      intPtr(res.Exit),
	}.Write(cfg.Stderr)
	return res.Exit
}

// classifyNoResult explains why a result is unavailable, by asking
// the drop box what it knows about the id (read-only; the gateway
// wrote the request file, so it can stat it). The three cases map to
// three teachings: keep waiting, re-file, or bad id.
func classifyNoResult(cfg Config, id string) string {
	dir := cfg.RequestsDir
	if dir == "" {
		dir = approval.RequestsDir
	}
	fi, err := os.Lstat(approval.RequestPath(dir, id))
	if err != nil {
		return fmt.Sprintf("no result for %s — no live request with this id (swept, or never filed; ids come from approval_required responses)", id)
	}
	if cfg.Now().Sub(fi.ModTime()) > approval.RequestTTL {
		return fmt.Sprintf("request %s expired — no operator answer within %s (refuse-by-default); re-run the command to file a fresh request", id, approval.RequestTTL)
	}
	return fmt.Sprintf("no result for %s yet — the request is pending operator approval; wait and re-check", id)
}

// fetchResult reads one result file, enforcing the TTL by mtime (the
// gateway cannot remove root-owned files; /run clears at boot).
func fetchResult(dir, id string, now time.Time) (approval.Result, error) {
	path := approval.ResultPath(dir, id)
	fi, err := os.Lstat(path)
	if err != nil {
		return approval.Result{}, fmt.Errorf("no such result")
	}
	if now.Sub(fi.ModTime()) > approval.ResultTTL {
		return approval.Result{}, fmt.Errorf("result expired")
	}
	body, err := approval.ReadFileSafe(path, approval.MaxResultFile)
	if err != nil {
		return approval.Result{}, err
	}
	return approval.ParseResult(body)
}

func intPtr(i int) *int { return &i }
