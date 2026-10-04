package control

// Signed-approval transport (§9, FIDO2): approver key management and
// the `sysh approve <id> --sig` verification path, exercised with
// stock ssh-keygen. The live touch of a hardware sk- key cannot be
// unit-tested; the cryptographic path is identical for plain keys.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApproverRoundtrip(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	old := approversDir
	approversDir = t.TempDir()
	defer func() { approversDir = old }()

	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH4FBGMBaWDP+yBSrIT2DdJGz0B7ZfCw1oMjwiCXMGfw test-approver@example"
	setStdin(pub)
	if code := cmdApprover([]string{"add", "alice"}); code != 0 {
		t.Fatalf("add exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(approversDir, "alice.pub")); err != nil {
		t.Fatal("alice.pub not written")
	}

	// duplicate refused
	setStdin(pub)
	if code := cmdApprover([]string{"add", "alice"}); code != 1 {
		t.Fatalf("duplicate add exit %d", code)
	}
	// bad name refused
	setStdin(pub)
	if code := cmdApprover([]string{"add", "Alice!"}); code != 64 {
		t.Fatalf("bad-name exit %d", code)
	}
	// options refused (an approver key is not an agent key)
	setStdin("restrict " + pub)
	if code := cmdApprover([]string{"add", "mallory"}); code != 1 {
		t.Fatalf("options add exit %d", code)
	}
	// garbage refused
	setStdin("not a key at all")
	if code := cmdApprover([]string{"add", "garbage"}); code != 1 {
		t.Fatalf("garbage add exit %d", code)
	}

	if code := cmdApprover([]string{"list"}); code != 0 {
		t.Fatalf("list exit %d", code)
	}
	if code := cmdApprover([]string{"remove", "alice"}); code != 0 {
		t.Fatalf("remove exit %d", code)
	}
	if code := cmdApprover([]string{"remove", "alice"}); code != 1 {
		t.Fatalf("double remove exit %d", code)
	}
}

// sshKeygen runs the stock binary or skips the test.
func sshKeygen(t *testing.T, args ...string) string {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func signFile(t *testing.T, keyPath, namespace, file string) string {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	_ = os.Remove(file + ".sig") // ssh-keygen prompts on overwrite; never reuse a stale sig
	out, err := exec.Command(bin, "-Y", "sign", "-f", keyPath, "-n", namespace, file).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, out)
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		t.Fatalf("signature file: %v", err)
	}
	return string(sig)
}

func TestApproveSignedFlow(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	oldApprovers := approversDir
	approversDir = t.TempDir()
	defer func() { approversDir = oldApprovers }()

	// throwaway operator keypair, registered as an approver
	dir := t.TempDir()
	key := filepath.Join(dir, "approver_ed25519")
	sshKeygen(t, "-t", "ed25519", "-N", "", "-C", "test-approver", "-f", key)
	setStdin(mustRead(t, key+".pub"))
	if code := cmdApprover([]string{"add", "alice"}); code != 0 {
		t.Fatalf("approver add exit %d", code)
	}

	argv := []string{"/usr/bin/systemctl", "restart", "nginx"}
	req := seedRequest(t, argv, 5*time.Second)

	// the operator fetches the exact bytes and signs them locally
	setStdin("")
	if code := cmdApprove([]string{"--show", req.ID}); code != 0 {
		t.Fatalf("show exit %d", code)
	}
	bodyPath := filepath.Join(requestsDir, req.ID)
	sig := signFile(t, key, approvalNamespace, bodyPath)

	executed := false
	runApproved = func(path string, args []string, timeout int, id string) execOutcome {
		executed = true
		return execOutcome{Exit: 0, Stdout: "restarted\n", DurationMS: 11}
	}
	auditSink = nil

	setStdin(sig)
	if code := cmdApprove([]string{"--sig", req.ID}); code != 0 {
		t.Fatalf("signed approve exit %d", code)
	}
	if !executed {
		t.Fatal("signed approval did not execute")
	}
	if _, err := os.Stat(filepath.Join(resultsDir, req.ID)); err != nil {
		t.Fatal("result not written")
	}
}

func TestApproveSignedRefusals(t *testing.T) {
	base := newTestEnv(t)
	_ = base
	installApprovalPolicy(t, base)
	oldApprovers := approversDir
	approversDir = t.TempDir()
	defer func() { approversDir = oldApprovers }()

	// registered approver + an unregistered stranger
	dir := t.TempDir()
	good := filepath.Join(dir, "good_ed25519")
	bad := filepath.Join(dir, "bad_ed25519")
	sshKeygen(t, "-t", "ed25519", "-N", "", "-C", "good", "-f", good)
	sshKeygen(t, "-t", "ed25519", "-N", "", "-C", "stranger", "-f", bad)
	setStdin(mustRead(t, good+".pub"))
	if code := cmdApprover([]string{"add", "alice"}); code != 0 {
		t.Fatalf("approver add exit %d", code)
	}

	runApproved = func(path string, args []string, timeout int, id string) execOutcome {
		t.Fatal("a refused signature must never execute")
		return execOutcome{Exit: 1}
	}
	auditSink = nil

	// scratch copies to sign (signing the drop-box files directly
	// would race the cleanup between subtests)
	req := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "nginx"}, 5*time.Second)
	bodyCopy := filepath.Join(dir, "nginx.body")
	if err := os.WriteFile(bodyCopy, mustReadBytes(t, filepath.Join(requestsDir, req.ID)), 0o600); err != nil {
		t.Fatal(err)
	}
	other := seedRequest(t, []string{"/usr/bin/systemctl", "restart", "mariadb"}, 5*time.Second)
	otherCopy := filepath.Join(dir, "mariadb.body")
	if err := os.WriteFile(otherCopy, mustReadBytes(t, filepath.Join(requestsDir, other.ID)), 0o600); err != nil {
		t.Fatal(err)
	}

	// [1] signature from an unregistered key
	sig := signFile(t, bad, approvalNamespace, bodyCopy)
	setStdin(sig)
	if code := cmdApprove([]string{"--sig", req.ID}); code != 1 {
		t.Fatalf("unregistered key exit %d", code)
	}
	assertPending(t, req.ID)

	// [2] signature over different bytes (another request)
	sig = signFile(t, good, approvalNamespace, bodyCopy) // signs the nginx bytes
	setStdin(sig)
	if code := cmdApprove([]string{"--sig", other.ID}); code != 1 {
		t.Fatalf("cross-request signature exit %d", code)
	}
	assertPending(t, other.ID)

	// [3] wrong namespace (e.g. a git signature replayed)
	sig = signFile(t, good, "git", otherCopy)
	setStdin(sig)
	if code := cmdApprove([]string{"--sig", other.ID}); code != 1 {
		t.Fatalf("wrong-namespace signature exit %d", code)
	}
	assertPending(t, other.ID)

	// [4] not a signature at all
	setStdin("hello there")
	if code := cmdApprove([]string{"--sig", other.ID}); code != 1 {
		t.Fatalf("garbage stdin exit %d", code)
	}
	assertPending(t, other.ID)
}

func assertPending(t *testing.T, id string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(requestsDir, id)); err != nil {
		t.Fatalf("request %s must stay pending after refusal: %v", id, err)
	}
}

func mustReadBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
