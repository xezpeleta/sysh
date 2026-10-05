package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/result"
)

// testConfig builds a Config wired to a temp policy environment.
func testConfig(t *testing.T, policyDoc string) (Config, *audit.Recorder, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir, err := os.MkdirTemp(cacheBase(t), "sysh-gw-*")
	if err != nil {
		t.Skipf("cannot create test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(policyDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	// directory ancestors must satisfy the fail-closed loader
	// (cache dir is user-owned, not world-writable).

	keysMap := filepath.Join(dir, "keys.map")
	os.WriteFile(keysMap, []byte(""), 0o644)
	docsDir := filepath.Join(dir, "docs")
	os.MkdirAll(docsDir, 0o755)

	var stdout, stderr bytes.Buffer
	rec := &audit.Recorder{}
	cfg := Config{
		PolicyPath:  policyPath,
		KeysMapPath: keysMap,
		DocsDir:     docsDir,
		Tripwire:    filepath.Join(dir, "tripwire"), // does not exist
		HomeDir:     dir,
		PolicyOwner: os.Getuid(),
		Sink:        rec,
		Scopes:      false, // no systemd-run in unit tests
		Stdin:       strings.NewReader(""),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Getenv:      func(string) string { return "" },
		Now:         time.Now,
	}
	return cfg, rec, &stdout, &stderr
}

func cacheBase(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("no cache dir: %v", err)
	}
	return base
}

const execPolicy = `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/bin/echo"]
path = "/bin/echo"
rest = "[a-zA-Z0-9@._\\-]*"

[[rule]]
argv = ["/usr/bin/systemctl", "status", "[a-z-]+"]
path = "/usr/bin/systemctl"
timeout = 30

[[rule]]
argv = ["find"]
deny = true
`

func TestRunExecChild(t *testing.T) {
	cfg, rec, stdout, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "/bin/echo hello")
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "hello\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	// exactly one structured result line, class=exec
	line := lastJSONLine(stderr.String())
	if !strings.Contains(line, `"class":"exec"`) || !strings.Contains(line, `"exit":0`) {
		t.Fatalf("result line = %s", line)
	}
	// fail-closed pre-exec event + post-exec outcome event
	if len(rec.Events) < 2 {
		t.Fatalf("expected pre+post events, got %d", len(rec.Events))
	}
	pre, post := rec.Events[0], rec.Events[len(rec.Events)-1]
	if pre.Phase != "pre" || pre.Decision != audit.DecisionAllow {
		t.Errorf("pre event: %+v", pre)
	}
	if post.Phase != "post" || post.Exit != 0 || post.DurationMS < 0 {
		t.Errorf("post event: %+v", post)
	}
	if post.Argv[0] != "/bin/echo" {
		t.Errorf("argv not recorded: %+v", post.Argv)
	}
}

func TestRunDenyNoRule(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "/bin/rm -rf /")
	if code != 125 {
		t.Fatalf("exit code %d, want 125", code)
	}
	line := lastJSONLine(stderr.String())
	if !strings.Contains(line, `"class":"denied"`) {
		t.Fatalf("result line = %s", line)
	}
}

func TestRunDenyRulePrefix(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	// deny rule has prefix semantics: find with any args is denied
	code := Run(cfg, "find / -name x")
	if code != 125 {
		t.Fatalf("exit code %d, want 125", code)
	}
	if !strings.Contains(stderr.String(), `"class":"denied"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunMalformedArgv(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "/bin/echo \x1b[31mx") // terminal escape byte
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if !strings.Contains(stderr.String(), `"class":"malformed"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunLockdown(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	// plant the tripwire
	if err := os.WriteFile(cfg.Tripwire, []byte("lockdown"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfg.Tripwire)
	code := Run(cfg, "/bin/echo hello")
	if code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `"class":"lockdown"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
	// even builtins are refused in lockdown
	cfg2, _, _, _ := testConfig(t, execPolicy)
	os.WriteFile(cfg2.Tripwire, []byte("lockdown"), 0o644)
	if code := Run(cfg2, "sy-policy"); code != 2 {
		t.Fatalf("builtin in lockdown: exit %d", code)
	}
}

func TestRunPolicyFailClosed(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	// make the policy world-writable → loader must refuse
	os.Chmod(cfg.PolicyPath, 0o666)
	code := Run(cfg, "/bin/echo hello")
	if code != 125 {
		t.Fatalf("exit code %d, want 125 (fail closed)", code)
	}
	if !strings.Contains(stderr.String(), "fail closed") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	os.Chmod(cfg.PolicyPath, 0o644)
	// missing policy → also fail closed
	cfg.PolicyPath = cfg.PolicyPath + ".missing"
	if code := Run(cfg, "/bin/echo hello"); code != 125 {
		t.Fatalf("missing policy: exit %d", code)
	}
}

func TestRunPrivilegedWithoutGrantFails(t *testing.T) {
	doc := `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/bin/echo", "danger"]
path = "/bin/echo"
privileged = true
ack = true
timeout = 10
`
	cfg, rec, _, _ := testConfig(t, doc)
	code := Run(cfg, "/bin/echo danger")
	// On a host without the matching sudoers grant, sudo -n refuses:
	// the argv gains nothing. (With a grant — the operator-installed
	// case — the same path executes as root; verified live on the
	// deployment host.)
	if code == 0 {
		t.Fatalf("privileged argv without a sudoers grant must not succeed (exit %d)", code)
	}
	// The attempt is fully attributed: pre + post events, PRIV marked.
	var sawPre, sawPost bool
	for _, ev := range rec.Events {
		if ev.Privileged && ev.Phase == "pre" && ev.Decision == audit.DecisionAllow {
			sawPre = true
		}
		if ev.Privileged && ev.Phase == "post" {
			sawPost = true
		}
	}
	if !sawPre || !sawPost {
		t.Fatalf("privileged attribution incomplete (pre=%v post=%v): %+v", sawPre, sawPost, rec.Events)
	}
}

func TestWrapSudo(t *testing.T) {
	argv, path, err := wrapSudo([]string{"/usr/bin/systemctl", "restart", "nginx"}, "/usr/bin/systemctl")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SudoPath, "-n", "--", "/usr/bin/systemctl", "restart", "nginx"}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("wrapped argv = %v, want %v", argv, want)
	}
	if path != SudoPath {
		t.Fatalf("wrapped path = %q", path)
	}
}

func TestRunBuiltinSyPolicy(t *testing.T) {
	cfg, _, stdout, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "sy-policy")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `[[rule]]`) {
		t.Fatalf("sy-policy output missing policy body: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `"class":"builtin"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunBuiltinSyDocs(t *testing.T) {
	cfg, _, stdout, _ := testConfig(t, execPolicy)
	os.WriteFile(cfg.DocsDir+"/runbook.md", []byte("# runbook\nrestart nginx with systemctl\n"), 0o644)

	if code := Run(cfg, "sy-docs"); code != 0 || !strings.Contains(stdout.String(), "runbook") {
		t.Fatalf("sy-docs list: exit code %d, stdout %q", code, stdout.String())
	}
	stdout.Reset()
	if code := Run(cfg, "sy-docs runbook"); code != 0 || !strings.Contains(stdout.String(), "restart nginx") {
		t.Fatalf("sy-docs runbook: exit %d, stdout %q", code, stdout.String())
	}
	stdout.Reset()
	// path traversal attempts are rejected
	for _, bad := range []string{"sy-docs ../policy", "sy-docs .hidden", "sy-docs /etc/passwd", "sy-docs a/b"} {
		if code := Run(cfg, bad); code == 0 {
			t.Errorf("sy-docs accepted %q", bad)
		}
	}
}

func TestRunResultNoResult(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	cfg.ResultsDir = filepath.Join(cfg.HomeDir, "results")
	code := Run(cfg, "sysh-result req_0123456789ab")
	if code != result.ExitNoResult {
		t.Fatalf("exit %d, want %d", code, result.ExitNoResult)
	}
	if !strings.Contains(stderr.String(), `"class":"result_unavailable"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
	// malformed id: usage refusal, same class
	code = Run(cfg, "sysh-result nonsense")
	if code != result.ExitNoResult {
		t.Fatalf("exit %d, want %d", code, result.ExitNoResult)
	}
}

func TestRunResultClassification(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	reqDir := filepath.Join(cfg.HomeDir, "requests")
	os.MkdirAll(reqDir, 0o755)
	cfg.RequestsDir = reqDir
	cfg.ResultsDir = filepath.Join(cfg.HomeDir, "results")
	id := "req_0123456789ab"

	// missing: no request file, no result file
	stderr.Reset()
	code := Run(cfg, "sysh-result "+id)
	if code != result.ExitNoResult {
		t.Fatalf("exit %d, want %d", code, result.ExitNoResult)
	}
	if !strings.Contains(stderr.String(), "no live request") {
		t.Fatalf("missing case: %s", stderr.String())
	}

	// pending: fresh request file in the drop box
	req := approval.Request{ID: id, Argv: []string{"/usr/bin/uptime"}, Time: cfg.Now()}
	body, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(reqDir, id), body, 0o640); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	code = Run(cfg, "sysh-result "+id)
	if code != result.ExitNoResult {
		t.Fatalf("exit %d, want %d", code, result.ExitNoResult)
	}
	if !strings.Contains(stderr.String(), "pending operator approval") {
		t.Fatalf("pending case: %s", stderr.String())
	}

	// expired: request file older than the TTL
	old := cfg.Now().Add(-approval.RequestTTL - time.Minute)
	if err := os.Chtimes(filepath.Join(reqDir, id), old, old); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	code = Run(cfg, "sysh-result "+id)
	if code != result.ExitNoResult {
		t.Fatalf("exit %d, want %d", code, result.ExitNoResult)
	}
	if !strings.Contains(stderr.String(), "expired") || !strings.Contains(stderr.String(), "re-run the command") {
		t.Fatalf("expired case: %s", stderr.String())
	}
}

func TestRunResultFetch(t *testing.T) {
	cfg, _, stdout, stderr := testConfig(t, execPolicy)
	dir := filepath.Join(cfg.HomeDir, "results")
	os.MkdirAll(dir, 0o755)
	res := approval.Result{
		ID: "req_0123456789ab", Argv: []string{"/bin/echo", "hi"},
		Exit: 7, Stdout: "captured output\n",
	}
	body, _ := json.Marshal(res)
	if err := os.WriteFile(filepath.Join(dir, res.ID), body, 0o640); err != nil {
		t.Fatal(err)
	}
	cfg.ResultsDir = dir
	code := Run(cfg, "sysh-result req_0123456789ab")
	if code != 7 {
		t.Fatalf("exit %d, want 7 (child exit passes through)", code)
	}
	if !strings.Contains(stdout.String(), "captured output") {
		t.Fatalf("stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `"class":"result"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunApprovalRequest(t *testing.T) {
	doc := `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "[a-z][a-z0-9\\-]*"]
path = "/usr/bin/systemctl"
timeout = 30
privileged = true
approval = true

[[rule]]
argv = ["/usr/sbin/reboot"]
path = "/usr/sbin/reboot"
timeout = 30
privileged = true
approval = true
ack = true
`
	cfg, rec, _, stderr := testConfig(t, doc)
	reqDir := filepath.Join(cfg.HomeDir, "requests")
	os.MkdirAll(reqDir, 0o755)
	cfg.RequestsDir = reqDir

	code := Run(cfg, "/usr/bin/systemctl restart nginx")
	if code != result.ExitApproval {
		t.Fatalf("exit %d, want %d; stderr: %s", code, result.ExitApproval, stderr.String())
	}
	line := stderr.String()
	if !strings.Contains(line, `"class":"approval_required"`) {
		t.Fatalf("stderr: %s", line)
	}
	var rl result.Line
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &rl); err != nil {
		t.Fatal(err)
	}
	if !approval.ValidID(rl.RequestID) {
		t.Fatalf("request id %q not well-formed", rl.RequestID)
	}
	// request file exists with the claimed argv
	body, err := approval.ReadFileSafe(filepath.Join(reqDir, rl.RequestID), 1<<16)
	if err != nil {
		t.Fatalf("request file: %v", err)
	}
	req, err := approval.ParseRequest(body)
	if err != nil {
		t.Fatalf("request parse: %v", err)
	}
	if len(req.Argv) != 3 || req.Argv[2] != "nginx" {
		t.Fatalf("request argv: %v", req.Argv)
	}
	// audit: one request event
	n := 0
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionRequest {
			n++
			if !ev.Privileged {
				t.Fatal("request event not marked privileged")
			}
		}
	}
	if n != 1 {
		t.Fatalf("got %d request events, want 1", n)
	}

	// identical request dedupes to the same id
	stderr.Reset()
	code = Run(cfg, "/usr/bin/systemctl restart nginx")
	if code != result.ExitApproval {
		t.Fatalf("second exit %d", code)
	}
	var rl2 result.Line
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr.String())), &rl2); err != nil {
		t.Fatal(err)
	}
	if rl2.RequestID != rl.RequestID {
		t.Fatalf("dedupe failed: %s vs %s", rl2.RequestID, rl.RequestID)
	}
	// audit fail-closed: no record, no request
	cfg2, rec2, _, _ := testConfig(t, doc)
	cfg2.RequestsDir = reqDir
	cfg2.Sink = failSink{}
	if code := Run(cfg2, "/usr/bin/systemctl restart nginx"); code != result.ExitDenied {
		t.Fatalf("fail-closed exit %d, want denied", code)
	}
	if len(rec2.Events) != 0 && rec2.Events[0].Decision != audit.DecisionInternal {
		// internal event is fine; no request event may exist
		for _, ev := range rec2.Events {
			if ev.Decision == audit.DecisionRequest {
				t.Fatal("request event emitted despite sink failure")
			}
		}
	}
}

type failSink struct{}

func (failSink) Emit(ev audit.Event) error { return fmt.Errorf("sink down") }

func TestRunPermissiveMode(t *testing.T) {
	doc := `
version = 2
mode = "permissive"

[[rule]]
argv = ["find"]
deny = true
`
	cfg, rec, stdout, stderr := testConfig(t, doc)
	code := Run(cfg, "/bin/echo permissive")
	if code != 0 || stdout.String() != "permissive\n" {
		t.Fatalf("permissive exec failed: exit %d stderr %s", code, stderr.String())
	}
	// deny still applies
	if code := Run(cfg, "find /"); code != 125 {
		t.Fatalf("permissive deny: exit %d", code)
	}
	if len(rec.Events) < 2 {
		t.Fatalf("events not recorded in permissive mode: %+v", rec.Events)
	}
}

func TestRunAuditSinkFailClosed(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	cfg.Sink = failingSink{}
	code := Run(cfg, "/bin/echo hello")
	if code != 125 {
		t.Fatalf("exit %d, want 125 (fail closed on sink error)", code)
	}
	if !strings.Contains(stderr.String(), "fail closed") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunTimeout(t *testing.T) {
	doc := `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/bin/sleep"]
path = "/bin/sleep"
timeout = 1
rest = "[0-9]+"
`
	cfg, _, _, stderr := testConfig(t, doc)
	start := time.Now()
	code := Run(cfg, "/bin/sleep 30")
	elapsed := time.Since(start)
	if code != 124 {
		t.Fatalf("exit %d, want 124 (timeout)", code)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("timeout took %v; child not killed", elapsed)
	}
	if !strings.Contains(stderr.String(), `"class":"timeout"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunChildExitCodePassesThrough(t *testing.T) {
	doc := execPolicy + `
[[rule]]
argv = ["/bin/false"]
path = "/bin/false"
`
	cfg, _, _, stderr := testConfig(t, doc)
	code := Run(cfg, "/bin/false")
	if code != 1 {
		t.Fatalf("child exit code %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), `"exit":1`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestRunOutputCap(t *testing.T) {
	doc := `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/yes"]
path = "/usr/bin/yes"
timeout = 30
`
	if _, err := os.Stat("/usr/bin/yes"); err != nil {
		t.Skip("no /usr/bin/yes")
	}
	cfg, _, stdout, stderr := testConfig(t, doc)
	code := Run(cfg, "/usr/bin/yes")
	if code != 124 {
		t.Fatalf("exit %d, want 124 (output cap kill)", code)
	}
	if stdout.Len() > (1<<20)+4096 {
		t.Fatalf("stdout far exceeds cap: %d bytes", stdout.Len())
	}
	if !strings.Contains(stderr.String(), `"class":"output_truncated"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

type failingSink struct{}

func (failingSink) Emit(ev audit.Event) error { return errSinkDown }

var errSinkDown = &sinkError{}

type sinkError struct{}

func (*sinkError) Error() string { return "journal sink down" }

func lastJSONLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], `"sysh":1`) {
			return lines[i]
		}
	}
	return ""
}

// An expired keys.map TTL refuses everything the key tries — before
// the policy is even consulted — with the standard deny exit, class,
// and journal record. A future expiry (or none) must not interfere.
func TestRunKeyExpired(t *testing.T) {
	line, fp := genKeyLine(t, "test-agent/expired")

	dir := t.TempDir()
	authFile := filepath.Join(dir, "user_auth")
	if err := os.WriteFile(authFile, []byte("publickey "+line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	build := func(expires string) (Config, *audit.Recorder, *bytes.Buffer) {
		cfg, rec, _, stderr := testConfig(t, execPolicy)
		if expires != "" {
			os.WriteFile(cfg.KeysMapPath, []byte(fp+" test-agent/expired expires:"+expires+"\n"), 0o644)
		}
		cfg.Getenv = func(k string) string {
			if k == "SSH_USER_AUTH" {
				return authFile
			}
			return ""
		}
		cfg.Now = func() time.Time { return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) }
		return cfg, rec, stderr
	}

	// expired: allowed argv still denied, exit 125, one deny event
	cfg, rec, stderr := build("2025-05-01T00:00:00Z")
	code := Run(cfg, "/bin/echo hello")
	if code != 125 {
		t.Fatalf("expired key: exit %d, want 125", code)
	}
	out := stderr.String()
	if !strings.Contains(out, `"class":"denied"`) || !strings.Contains(out, "expired") {
		t.Fatalf("expired key result line: %s", out)
	}
	if len(rec.Events) != 1 || rec.Events[0].Decision != audit.DecisionDeny ||
		rec.Events[0].KeyID != "test-agent/expired" {
		t.Fatalf("expired key events: %+v", rec.Events)
	}

	// not yet expired: the same setup must run
	cfg, _, stderr = build("2025-06-10T00:00:00Z")
	if code := Run(cfg, "/bin/echo hello"); code != 0 {
		t.Fatalf("valid TTL key: exit %d, stderr %s", code, stderr.String())
	}

	// no expiry at all: identity maps, exec runs (regression)
	cfg, _, stderr = build("")
	if code := Run(cfg, "/bin/echo hello"); code != 0 {
		t.Fatalf("no-TTL key: exit %d, stderr %s", code, stderr.String())
	}
}

// ---- root mode (§6.9): total freedom, recording only --------------------

func TestRunRootMode(t *testing.T) {
	doc := `
version = 2
mode = "root"
timeout = 30

[[rule]]
argv = ["/usr/bin/rm"]
deny = true
`
	cfg, rec, out, _ := testConfig(t, doc)

	// allowed argv: runs as root via the wildcard sudoers grant. On a
	// host without the grant sudo -n refuses — the argv gains nothing,
	// and the attempt is journaled with PRIV marked.
	code := Run(cfg, "/bin/echo freedom")
	if code == 0 {
		t.Fatalf("root-mode argv without the sudoers grant must not succeed (exit %d)", code)
	}
	var sawPriv bool
	for _, ev := range rec.Events {
		if ev.Privileged && ev.Decision == audit.DecisionAllow {
			sawPriv = true
		}
	}
	if !sawPriv {
		t.Fatalf("root-mode exec must be PRIV-marked: %+v", rec.Events)
	}
	if !strings.Contains(out.String(), "freedom") && code != 125 {
		t.Logf("output: %s", out.String())
	}

	// deny rules still deny — the one control that still means something
	cfg2, rec2, _, _ := testConfig(t, doc)
	if code := Run(cfg2, "/usr/bin/rm -rf /"); code != result.ExitDenied {
		t.Fatalf("deny rule must hold in root mode (exit %d)", code)
	}
	denied := false
	for _, ev := range rec2.Events {
		if ev.Decision == audit.DecisionDeny {
			denied = true
		}
	}
	if !denied {
		t.Fatal("root-mode deny must be journaled")
	}
}
