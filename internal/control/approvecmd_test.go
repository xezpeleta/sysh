package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
)

// approvalPolicy: one pattern approval rule (restart a lowercase unit)
// and one literal approval rule (reboot). Paths point at /bin/true so
// the fake linter FS is happy.
const approvalPolicy = `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "[a-z][a-z0-9\\-]*"]
path = "/usr/bin/systemctl"
timeout = 30
privileged = true
approval = true

[[rule]]
argv = ["/bin/true"]
path = "/bin/true"
timeout = 10
privileged = true
approval = true
`

// seedRequest writes a valid request file into the drop box.
func seedRequest(t *testing.T, argv []string, age time.Duration) approval.Request {
	t.Helper()
	req := approval.Request{
		ID:          approval.ID(argv, "agent/host"),
		KeyID:       "agent/host",
		Fingerprint: "SHA256:fake",
		Argv:        argv,
		Time:        nowFn().Add(-age),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(requestsDir, req.ID), body, 0o640); err != nil {
		t.Fatal(err)
	}
	return req
}

func installApprovalPolicy(t *testing.T, env string) {
	t.Helper()
	doc := approvalPolicy
	// make the linter FS know the binaries
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/systemctl", 0o755, 0).
		addFile("/bin/true", 0o755, 0)
	if err := os.WriteFile(policyPath, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	// chown to ownerUID so the fail-closed loader accepts it
	_ = os.Chown(policyPath, ownerUID, -1)
}

func TestApproveFullFlow(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	argv := []string{"/usr/bin/systemctl", "restart", "nginx"}
	req := seedRequest(t, argv, 5*time.Second)

	executed := ""
	runApproved = func(path string, args []string, timeout int, id string) execOutcome {
		executed = path + " " + strings.Join(args, " ") + " timeout=" + strconv.Itoa(timeout)
		return execOutcome{Exit: 0, Stdout: "restarted\n", DurationMS: 42}
	}
	setStdin("yes\nnginx\n")

	rec := &audit.Recorder{}
	auditSink = rec

	if code := cmdApprove([]string{req.ID}); code != 0 {
		t.Fatalf("approve exit %d", code)
	}
	if executed != "/usr/bin/systemctl restart nginx timeout=30" {
		t.Fatalf("executed: %q", executed)
	}
	// request consumed
	if _, err := os.Stat(filepath.Join(requestsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("request file not removed")
	}
	// result written, fetchable, content intact
	body, err := approval.ReadFileSafe(filepath.Join(resultsDir, req.ID), 1<<18)
	if err != nil {
		t.Fatalf("result file: %v", err)
	}
	res, err := approval.ParseResult(body)
	if err != nil {
		t.Fatalf("result parse: %v", err)
	}
	if res.Exit != 0 || res.Stdout != "restarted\n" || res.DurationMS != 42 {
		t.Fatalf("result: %+v", res)
	}
	// audit: approve decision recorded with the request's argv
	found := false
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionApprove && ev.Argv != nil && ev.Argv[2] == "nginx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no approve event: %+v", rec.Events)
	}
}

func TestApproveWrongTypedArgument(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 5*time.Second)

	setStdin("yes\nWRONG\n")
	if code := cmdApprove([]string{req.ID}); code != 1 {
		t.Fatalf("exit %d, want refusal", code)
	}
	// request stays pending; nothing executed; no result
	if _, err := os.Stat(filepath.Join(requestsDir, req.ID)); err != nil {
		t.Fatalf("request removed on typo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(resultsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("result written despite typo")
	}
}

func TestApproveDeclined(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 5*time.Second)
	setStdin("no\n")
	if code := cmdApprove([]string{req.ID}); code != 1 {
		t.Fatalf("exit %d, want abort", code)
	}
	if _, err := os.Stat(filepath.Join(requestsDir, req.ID)); err != nil {
		t.Fatalf("request removed on decline: %v", err)
	}
}

func TestApprovePolicyRefusal(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	// argv the policy does not authorize: an operator cannot approve
	// what policy forbids, no matter what the request file claims
	req := seedRequest(t, []string{"/usr/bin/rm", "-rf", "/"}, 5*time.Second)
	setStdin("yes\n")
	if code := cmdApprove([]string{req.ID}); code != 1 {
		t.Fatalf("exit %d, want policy refusal", code)
	}
	if _, err := os.Stat(filepath.Join(resultsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("result written for unauthorized argv")
	}
}

func TestApproveExpired(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 15*time.Minute)
	setStdin("yes\nnginx\n")
	if code := cmdApprove([]string{req.ID}); code != 1 {
		t.Fatalf("exit %d, want expiry refusal", code)
	}
	if _, err := os.Stat(filepath.Join(requestsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("expired request not removed")
	}
}

func TestApproveRequiresTTY(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 5*time.Second)
	stdinIsTTY = func() bool { return false }
	setStdin("yes\nnginx\n")
	if code := cmdApprove([]string{req.ID}); code != 1 {
		t.Fatalf("exit %d, want TTY refusal", code)
	}
	// nothing happened
	if _, err := os.Stat(filepath.Join(resultsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("result written without TTY")
	}
}

func TestDenyRequest(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 5*time.Second)
	rec := &audit.Recorder{}
	auditSink = rec
	if code := cmdDeny([]string{req.ID}); code != 0 {
		t.Fatalf("deny exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(requestsDir, req.ID)); !os.IsNotExist(err) {
		t.Fatal("request not removed")
	}
	rejected := false
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionReject {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("no reject event")
	}
}

func TestApprovalsListing(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	live := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 3*time.Second)
	old := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "apache2"}, 15*time.Minute)

	// capture stdout
	out := captureStdout(t, func() int { return cmdApprovals(nil) })

	if !strings.Contains(out, live.ID) || !strings.Contains(out, "nginx") {
		t.Fatalf("live request missing from listing:\n%s", out)
	}
	if !strings.Contains(out, old.ID) || !strings.Contains(out, "EXPIRED") {
		t.Fatalf("expired request not marked:\n%s", out)
	}

	js := captureStdout(t, func() int { return cmdApprovals([]string{"--json"}) })
	var rows []struct {
		ID      string   `json:"id"`
		Argv    []string `json:"argv"`
		Expired bool     `json:"expired"`
	}
	if err := json.Unmarshal([]byte(js), &rows); err != nil {
		t.Fatalf("json listing: %v\n%s", err, js)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: %d", len(rows))
	}
	for _, r := range rows {
		if r.ID == old.ID && !r.Expired {
			t.Fatal("expired row not flagged")
		}
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and
// returns what it printed.
func captureStdout(t *testing.T, fn func() int) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := fn()
	w.Close()
	os.Stdout = old
	buf := make([]byte, 64<<10)
	n, _ := r.Read(buf)
	if code != 0 {
		t.Fatalf("command exit %d", code)
	}
	return string(buf[:n])
}
