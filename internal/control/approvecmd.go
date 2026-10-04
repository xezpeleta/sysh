// Approval channel, root side (§9): sysh approvals / sysh approve /
// sysh deny. These commands run as root, invoked by the operator over
// plain root SSH (transport A). Approval chooses *when*; the root-owned
// policy chooses *what* — the approver re-matches every request argv
// against the installed policy before anything executes, and executes
// from its own in-memory copy, never from the request file.
package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/policy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// Paths (production defaults; vars for tests).
var (
	requestsDir = approval.RequestsDir
	resultsDir  = approval.ResultsDir
)

// Hooks the test suite stubs.
var (
	// stdinIsTTY: approve requires a real terminal (a pipe cannot
	// type challenge answers; §9). Over `ssh -t root@host` it is one.
	stdinIsTTY = stdinIsTTYImpl
	// runApproved executes one approved argv under containment and
	// returns the outcome. Production: systemd-run system scope,
	// TasksMax/MemoryMax, hard timeout, output caps. Tests stub it.
	runApproved = runApprovedProd
	// auditSink is where approval events land (same stream as the
	// gateway's, SYSLOG_IDENTIFIER=sysh).
	auditSink audit.Sink = audit.JournalSink{}
	// nowFn lets tests freeze time.
	nowFn = time.Now
)

func cmdApprovals(args []string) int {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else {
			fmt.Fprintf(os.Stderr, "usage: sysh approvals [--json]\n")
			return 64
		}
	}
	reqs, expired, errs := readRequests()
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "sysh approvals: %v\n", e)
	}
	if len(reqs)+len(expired) == 0 {
		fmt.Println("no pending requests")
		return 0
	}
	if asJSON {
		type row struct {
			ID      string   `json:"id"`
			Argv    []string `json:"argv"`
			Key     string   `json:"key"`
			AgeSec  int      `json:"age_sec"`
			Expired bool     `json:"expired"`
		}
		var rows []row
		for _, r := range reqs {
			rows = append(rows, row{r.ID, r.Argv, r.KeyID, int(nowFn().Sub(r.Time).Seconds()), false})
		}
		for _, r := range expired {
			rows = append(rows, row{r.ID, r.Argv, r.KeyID, int(nowFn().Sub(r.Time).Seconds()), true})
		}
		out, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	for _, r := range reqs {
		fmt.Printf("%s  age=%ds  key=%s\n  argv=%s\n", r.ID,
			int(nowFn().Sub(r.Time).Seconds()), r.KeyID, quoteJSON(r.Argv))
	}
	for _, r := range expired {
		fmt.Printf("%s  EXPIRED (age %ds) — re-request from the agent or ignore; it is refuse-by-default\n  argv=%s\n", r.ID,
			int(nowFn().Sub(r.Time).Seconds()), quoteJSON(r.Argv))
	}
	return 0
}

func cmdDeny(args []string) int {
	if len(args) != 1 || !approval.ValidID(args[0]) {
		fmt.Fprintln(os.Stderr, "usage: sysh deny <request-id>")
		return 64
	}
	req, err := loadRequest(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh deny: %v\n", err)
		return 1
	}
	emitApprovalEvent(audit.DecisionReject, req, "operator denied request", -1, 0)
	if err := os.Remove(approval.RequestPath(requestsDir, req.ID)); err != nil {
		fmt.Fprintf(os.Stderr, "sysh deny: request rejected but not removed: %v\n", err)
	}
	fmt.Printf("rejected %s\n", req.ID)
	return 0
}

func cmdApprove(args []string) int {
	// Modes: interactive (default), --show (print the exact bytes a
	// signature must cover), --sig (verify an ssh-keygen signature from
	// stdin instead of prompting — the FIDO2 transport, §9).
	var mode string
	var id string
	for _, a := range args {
		switch a {
		case "--sig", "--show":
			if mode != "" {
				fmt.Fprintln(os.Stderr, "usage: sysh approve <request-id> [--sig|--show]")
				return 64
			}
			mode = a
		default:
			if id != "" || !approval.ValidID(a) {
				fmt.Fprintln(os.Stderr, "usage: sysh approve <request-id> [--sig|--show]")
				return 64
			}
			id = a
		}
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "usage: sysh approve <request-id> [--sig|--show]")
		return 64
	}
	switch mode {
	case "--show":
		return approveShow(id)
	case "--sig":
		return approveSigned(id)
	}
	// Interactive: the typed-challenge path needs a real terminal.
	if !stdinIsTTY() {
		fmt.Fprintln(os.Stderr, "sysh approve: stdin must be a real terminal (use ssh -t, or a console); pipes are refused (for signed approvals: --sig)")
		return 1
	}
	ctx, code := beginApproval(id)
	if ctx == nil {
		return code
	}
	defer ctx.release()

	// Display exactly what will run, then challenge. Pattern-chosen
	// arguments (the only attacker-influenced content, §9) must be
	// typed by the human; a fully literal rule needs a plain yes.
	fmt.Printf("request %s\n  key:    %s (claimed)\n  argv:   %s\n  rule:   %d, timeout %ds\n  execute as root? [yes/no] ",
		ctx.req.ID, ctx.req.KeyID, quoteJSON(ctx.req.Argv), ctx.dec.RuleIdx, ctx.timeout)
	reader := bufio.NewReader(stdin)
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans != "yes" && ans != "y" {
		fmt.Println("aborted (request stays pending)")
		return 1
	}
	for _, pos := range patternPositions(ctx.dec.Rule, ctx.req.Argv) {
		arg := ctx.req.Argv[pos]
		fmt.Printf("type argument %d exactly as shown (%s): ", pos, arg)
		typed, _ := reader.ReadString('\n')
		if strings.TrimRight(typed, "\r\n") != arg {
			fmt.Println("mismatch — aborting (request stays pending)")
			return 1
		}
	}

	return finishApproval(ctx, fmt.Sprintf("approved by operator (rule %d)", ctx.dec.RuleIdx))
}

// approveShow prints the exact request file bytes to stdout (hints go
// to stderr): an operator signs precisely these bytes, and the server
// verifies against precisely these bytes — re-marshaling could drift.
func approveShow(id string) int {
	req, body, err := loadRequestRaw(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve --show: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "# request %s (key %s, claimed): sign these bytes with\n", req.ID, req.KeyID)
	fmt.Fprintf(os.Stderr, "#   ssh-keygen -Y sign -f <approver-key> -n sysh-approve <file>\n# and submit: sysh approve %s --sig < file.sig\n", req.ID)
	os.Stdout.Write(body)
	return 0
}

// approveSigned verifies an ssh-keygen signature over the exact
// request bytes from a registered approver key (namespace
// sysh-approve), then executes through the same gates as the
// interactive path. The touch, for sk-* keys, happened on the
// operator's device at sign time — that is the human in the loop; no
// terminal is required here.
func approveSigned(id string) int {
	ctx, code := beginApproval(id)
	if ctx == nil {
		return code
	}
	defer ctx.release()

	name, fp, err := verifyApprovalSignature(ctx.body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve --sig: %v (request stays pending)\n", err)
		return 1
	}
	fmt.Printf("signature ok: approver %s (%s)\n", name, fp)
	return finishApproval(ctx, fmt.Sprintf("approved by signed request, approver %s (%s, rule %d)", name, fp, ctx.dec.RuleIdx))
}

// approvalCtx carries one request through the shared approval gates.
type approvalCtx struct {
	req     approval.Request
	body    []byte // exact file bytes: what a signature must cover
	release func()
	dec     policy.Decision
	rule    *policy.Rule
	timeout int
}

// beginApproval runs the shared gates: strict load with id↔content
// binding, TTL, exclusive claim, and the policy re-check (approval
// chooses *when*; the root-owned policy chooses *what* — an operator
// cannot approve anything the policy does not authorize, no matter
// what the untrusted request file claims). Returns nil + exit code on
// refusal; the caller must defer ctx.release() on success.
func beginApproval(id string) (*approvalCtx, int) {
	req, body, err := loadRequestRaw(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve: %v\n", err)
		return nil, 1
	}
	if age := nowFn().Sub(req.Time); age > approval.RequestTTL {
		_ = os.Remove(approval.RequestPath(requestsDir, id))
		fmt.Fprintf(os.Stderr, "sysh approve: request expired (age %s > TTL %s); removed\n", age.Truncate(time.Second), approval.RequestTTL)
		return nil, 1
	}

	// Exclusive claim: exactly one approver may drive this request.
	// Every exit path releases it; a successful approval removes the
	// request itself, after which the release is a no-op.
	release, err := claimRequest(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve: %v\n", err)
		return nil, 1
	}

	pol, _, _, err := policy.Load(policyPath, ownerUID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve: policy unavailable (fail closed): %v\n", err)
		release()
		return nil, 1
	}
	compiled, err := policy.Compile(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve: policy uncompilable (fail closed): %v\n", err)
		release()
		return nil, 1
	}
	dec := compiled.Match(req.Argv)
	if !dec.Allowed || dec.Rule == nil || !dec.Rule.Privileged || !dec.Rule.Approval || dec.Rule.Deny {
		fmt.Fprintf(os.Stderr, "sysh approve: policy does not authorize this argv as an approval rule (rule changed since the request?) — refusing\n")
		release()
		return nil, 1
	}
	timeout := dec.Rule.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	return &approvalCtx{req: req, body: body, release: release, dec: dec, rule: dec.Rule, timeout: timeout}, 0
}

// finishApproval executes an approved request from the in-memory copy
// it was verified against, writes the result file, consumes the
// request, and emits the pre/post audit pair.
func finishApproval(ctx *approvalCtx, detail string) int {
	// Pre-exec record: the approval is the elevation event.
	emitApprovalEvent(audit.DecisionApprove, ctx.req, detail, -1, 0)

	out := runApproved(ctx.rule.Path, ctx.req.Argv[1:], ctx.timeout, ctx.req.ID)

	// Result file: the agent fetches it read-only via sysh-result.
	res := approval.Result{
		ID:         ctx.req.ID,
		Argv:       ctx.req.Argv,
		Exit:       out.Exit,
		DurationMS: out.DurationMS,
		Truncated:  out.Truncated,
		Stdout:     out.Stdout,
		Stderr:     out.Stderr,
		Time:       nowFn(),
	}
	if body, err := json.Marshal(res); err == nil {
		if err := writeResultFile(res.ID, body); err != nil {
			fmt.Fprintf(os.Stderr, "sysh approve: executed but result not written: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "sysh approve: result encode failed: %v\n", err)
	}
	if err := os.Remove(approval.RequestPath(requestsDir, ctx.req.ID)); err != nil {
		fmt.Fprintf(os.Stderr, "sysh approve: request not removed: %v\n", err)
	}

	emitApprovalEvent(audit.DecisionApprove, ctx.req, detail+" — execution finished", out.Exit, out.DurationMS)

	fmt.Printf("executed: exit=%d in %dms; the agent fetches the outcome with: sysh-result %s\n",
		out.Exit, out.DurationMS, ctx.req.ID)
	return 0
}

// execOutcome is what runApproved returns.
type execOutcome struct {
	Exit       int
	DurationMS int64
	Stdout     string
	Stderr     string
	Truncated  bool
}

// runApprovedProd executes the approved argv as root under a system
// scope with containment, mirroring the gateway's unprivileged
// containment (§6.7): TasksMax, MemoryMax, hard timeout, output caps.
func runApprovedProd(path string, args []string, timeoutSec int, id string) execOutcome {
	start := nowFn()
	unit := "sysh-approve-" + strings.TrimPrefix(id, "req_")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run",
		"--system", "--scope", "--quiet",
		"--unit", unit,
		"-p", fmt.Sprintf("TasksMax=%d", 256),
		"-p", "MemoryMax=1G",
		"--", path)
	cmd.Args = append(cmd.Args, args...)
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}

	var stdout, stderr bytes.Buffer
	truncated := false
	capped := func() { truncated = true }
	cmd.Stdout = &capWriter{buf: &stdout, trip: capped}
	cmd.Stderr = &capWriter{buf: &stderr, trip: capped}

	runErr := cmd.Run()
	code := 0
	if ctx.Err() == context.DeadlineExceeded {
		code = 124
	} else if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 125
		}
	}
	return execOutcome{
		Exit:       code,
		DurationMS: nowFn().Sub(start).Milliseconds(),
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Truncated:  truncated,
	}
}

// capWriter bounds captured output at the result-stream cap.
type capWriter struct {
	buf  *bytes.Buffer
	trip func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= approval.MaxResultStream {
		w.trip()
		return len(p), nil // drop
	}
	room := approval.MaxResultStream - w.buf.Len()
	if len(p) > room {
		p = p[:room]
		w.trip()
	}
	return w.buf.Write(p)
}

// loadRequest reads and validates one request file (§9 hygiene).
func loadRequest(id string) (approval.Request, error) {
	req, _, err := loadRequestRaw(id)
	return req, err
}

// loadRequestRaw additionally returns the exact file bytes: the
// signature transport verifies (and the operator signs) precisely
// these bytes, never a re-marshaled copy.
func loadRequestRaw(id string) (approval.Request, []byte, error) {
	path := approval.RequestPath(requestsDir, id)
	body, err := approval.ReadFileSafe(path, approval.MaxRequestFile)
	if err != nil {
		return approval.Request{}, nil, err
	}
	req, err := approval.ParseRequest(body)
	if err != nil {
		return approval.Request{}, nil, err
	}
	if req.ID != id {
		return approval.Request{}, nil, fmt.Errorf("request id mismatch (file claims %s)", req.ID)
	}
	// The id is deterministic over (argv, key): binding name to content
	// makes a tampered body unapprovable even before the policy re-check.
	if want := approval.ID(req.Argv, req.KeyID); want != id {
		return approval.Request{}, nil, fmt.Errorf("request id does not match its content (tampered?)")
	}
	return req, body, nil
}

// claimRequest takes exclusive control of a pending request via a
// root-owned O_EXCL marker in the drop box (the sticky bit on the box
// keeps sy from removing it): two operators approving concurrently
// cannot both execute — exactly one claim exists at any moment. A
// marker stranded by a crashed approver becomes stealable once it is
// older than the request TTL (the request itself is expired by then).
func claimRequest(id string) (release func(), err error) {
	mk := claimPath(id)
	open := func() (*os.File, error) {
		return os.OpenFile(mk, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	f, err := open()
	if os.IsExist(err) {
		if fi, se := os.Stat(mk); se == nil && nowFn().Sub(fi.ModTime()) > approval.RequestTTL {
			_ = os.Remove(mk) // stale claim from a crashed approver
			f, err = open()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("another approver holds this request (or a crashed approve left its marker; it is stealable after %s)", approval.RequestTTL)
	}
	f.Close()
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(mk) }) }, nil
}

// claimPath returns the approval marker path for a request id. The
// ".claimed" suffix is not a valid request id, so markers never appear
// in listings and the drop box sweeper ignores them.
func claimPath(id string) string {
	return approval.RequestPath(requestsDir, id) + ".claimed"
}

// verifyApprovalSignature reads an armored ssh-keygen signature
// (SSH SIGNATURE blob) from stdin and verifies it in-process over the
// exact request bytes, namespace sysh-approve, against the registered
// approver keys. Returns the matching approver name and key
// fingerprint on success.
//
// Properties: the signature is bound to these exact bytes (a sig over
// any other content fails), to this namespace (a git or other
// protocol signature fails), and to a registered key (an unknown key
// fails). For sk-* keys the token required a physical touch to
// produce it. Requests are TTL'd and single-use: a captured signature
// cannot approve anything else, nor the same request re-created later
// (a fresh request carries a fresh timestamp, hence fresh bytes).
func verifyApprovalSignature(body []byte) (name, fingerprint string, err error) {
	names, err := approverNames()
	if err != nil {
		return "", "", fmt.Errorf("approvers dir unreadable: %v", err)
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("no approvers registered (sysh approver add <name>)")
	}

	armored, err := readSignature(stdin)
	if err != nil {
		return "", "", err
	}
	sig, err := approval.ParseSSHSig([]byte(armored))
	if err != nil {
		return "", "", err
	}

	// The embedded signer key must be exactly one registered
	// approver's key - matched by key bytes, not by claimed name.
	var match string
	for _, n := range names {
		pub, err := os.ReadFile(approversDir + "/" + n + ".pub")
		if err != nil {
			continue
		}
		reg, _, _, _, err := ssh.ParseAuthorizedKey(pub)
		if err != nil {
			continue
		}
		if bytes.Equal(reg.Marshal(), sig.PublicKey.Marshal()) {
			match = n
			break
		}
	}
	if match == "" {
		return "", "", fmt.Errorf("signing key is not a registered approver")
	}
	if err := sig.Verify(body, approvalNamespace); err != nil {
		return "", "", err
	}
	return match, ssh.FingerprintSHA256(sig.PublicKey), nil
}

// approvalNamespace is the SSHSIG signature namespace for signed
// approvals: signatures made for any other namespace fail to verify.
const approvalNamespace = "sysh-approve"

// readSignature reads one armored ssh-keygen signature from r,
// size-capped; parsing and structural checks happen in ParseSSHSig.
func readSignature(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<17)) // 128 KiB hard cap
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// readRequests sweeps the drop box: live requests, expired ones, and
// per-file errors (unreadable/tampered entries are surfaced, never
// silently dropped). Refuses to list beyond MaxLiveRequests live
// entries (§9.3 approval-fatigue bound).
func readRequests() (live, expired []approval.Request, errs []error) {
	entries, err := os.ReadDir(requestsDir)
	if err != nil {
		return nil, nil, []error{err}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if approval.ValidID(e.Name()) && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		body, err := approval.ReadFileSafe(approval.RequestPath(requestsDir, n), approval.MaxRequestFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", n, err))
			continue
		}
		req, err := approval.ParseRequest(body)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", n, err))
			continue
		}
		if req.ID != n {
			errs = append(errs, fmt.Errorf("%s: claims id %s", n, req.ID))
			continue
		}
		if approval.ID(req.Argv, req.KeyID) != n {
			errs = append(errs, fmt.Errorf("%s: id does not match its content (tampered?)", n))
			continue
		}
		if nowFn().Sub(req.Time) > approval.RequestTTL {
			expired = append(expired, req)
		} else {
			live = append(live, req)
		}
	}
	if len(live) > approval.MaxLiveRequests {
		errs = append(errs, fmt.Errorf("%d live requests exceed the maximum of %d — refuse new ones until these are decided", len(live), approval.MaxLiveRequests))
	}
	return live, expired, errs
}

// patternPositions returns the argv positions whose values were chosen
// by a rule pattern (or rest) rather than a literal — the only
// attacker-influenced content in a request (§9).
func patternPositions(rule *policy.Rule, argv []string) []int {
	var pos []int
	for i, pat := range rule.Argv {
		if i < len(argv) && policy.IsPattern(pat) {
			pos = append(pos, i)
		}
	}
	if rule.Rest != "" && len(argv) > len(rule.Argv) {
		for i := len(rule.Argv); i < len(argv); i++ {
			pos = append(pos, i)
		}
	}
	return pos
}

// writeResultFile stores the outcome for the agent's read-only fetch.
func writeResultFile(id string, body []byte) error {
	if err := os.MkdirAll(resultsDir, 0o750); err != nil {
		return err
	}
	path := approval.ResultPath(resultsDir, id)
	if err := os.WriteFile(path, body, 0o640); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		_ = os.Chown(path, 0, gidOfSy())
	}
	return nil
}

// emitApprovalEvent writes one root-side approval event to the same
// journald stream as the gateway's (the journal's _UID=0 marks the
// root side; the request's key id is carried as claimed data).
func emitApprovalEvent(decision string, req approval.Request, detail string, exit int, durMS int64) {
	if auditSink == nil {
		return
	}
	ev := audit.Event{
		Time:        nowFn(),
		Decision:    decision,
		KeyID:       req.KeyID,
		Fingerprint: req.Fingerprint,
		Argv:        req.Argv,
		Mode:        "enforcing",
		Detail:      detail,
	}
	if exit >= 0 {
		ev.Exit = exit
		ev.DurationMS = durMS
		ev.Phase = "post"
	}
	_ = auditSink.Emit(ev)
}

func quoteJSON(argv []string) string {
	b, _ := json.Marshal(argv)
	return string(b)
}

// stdinIsTTYImpl reports whether stdin is a real terminal: the ioctl
// fails (ENOTTY) on pipes and files, which is exactly the refusal
// condition (§9).
func stdinIsTTYImpl() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// gidOfSy returns the gid of the sy group (the package creates it);
// on failure the result file simply stays root-owned (agent cannot
// read it — safe direction).
func gidOfSy() int {
	g, err := user.Lookup("sy")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return n
}
