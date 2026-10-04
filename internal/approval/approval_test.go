package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestIDDeterministic(t *testing.T) {
	a := ID([]string{"/usr/bin/systemctl", "restart", "nginx"}, "agent/host")
	b := ID([]string{"/usr/bin/systemctl", "restart", "nginx"}, "agent/host")
	c := ID([]string{"/usr/bin/systemctl", "restart", "nginx"}, "other/host")
	d := ID([]string{"/usr/bin/systemctl", "restart", "nginxg"}, "agent/host")
	if a != b || a == c || a == d {
		t.Fatalf("id derivation broken: %s %s %s %s", a, b, c, d)
	}
	if !ValidID(a) {
		t.Fatalf("derived id %q not valid", a)
	}
	for _, bad := range []string{"", "req_", "req_abc", "req_0123456789abX", "req_0123456789AB", "xreq_0123456789ab", "req_/etc/passwd"} {
		if ValidID(bad) {
			t.Fatalf("ValidID(%q) = true", bad)
		}
	}
}

func TestParseRequestStrict(t *testing.T) {
	good, err := json.Marshal(Request{
		ID: "req_0123456789ab", KeyID: "agent/host", Fingerprint: "AA:BB",
		Argv: []string{"/usr/bin/systemctl", "restart", "nginx"},
		Time: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(good); err != nil {
		t.Fatalf("good request rejected: %v", err)
	}

	// unknown field (forward-compat tampering) must be refused
	tampered := `{"id":"req_0123456789ab","key":"k","fingerprint":"f","argv":["/bin/true"],"time":"` +
		time.Now().Format(time.RFC3339) + `","extra":"x"}`
	if _, err := ParseRequest([]byte(tampered)); err == nil {
		t.Fatal("unknown field accepted")
	}

	// non-printable argv must be refused (the gateway only writes
	// printable ASCII; anything else is a tampered spool)
	bad, _ := json.Marshal(Request{
		ID: "req_0123456789ab", Argv: []string{"/bin/sh\ts-c"}, Time: time.Now(),
	})
	if _, err := ParseRequest(bad); err == nil {
		t.Fatal("non-printable argv accepted")
	}

	// bad id
	bad, _ = json.Marshal(Request{ID: "../../etc/passwd", Argv: []string{"/bin/true"}, Time: time.Now()})
	if _, err := ParseRequest(bad); err == nil {
		t.Fatal("path-shaped id accepted")
	}

	// garbage timestamp
	bad, _ = json.Marshal(Request{ID: "req_0123456789ab", Argv: []string{"/bin/true"}, Time: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := ParseRequest(bad); err == nil {
		t.Fatal("ancient timestamp accepted")
	}
}

func TestParseResultStrict(t *testing.T) {
	good, _ := json.Marshal(Result{ID: "req_0123456789ab", Argv: []string{"/bin/true"}, Exit: 0})
	if _, err := ParseResult(good); err != nil {
		t.Fatalf("good result rejected: %v", err)
	}
	oversized, _ := json.Marshal(Result{ID: "req_0123456789ab", Stdout: string(make([]byte, MaxResultStream+1))})
	if _, err := ParseResult(oversized); err == nil {
		t.Fatal("oversized stdout accepted")
	}
}

func TestReadFileSafeHygiene(t *testing.T) {
	dir := t.TempDir()

	// regular file: fine
	p := filepath.Join(dir, "ok")
	os.WriteFile(p, []byte("hello"), 0o644)
	if b, err := ReadFileSafe(p, 1<<16); err != nil || string(b) != "hello" {
		t.Fatalf("regular file: %v %q", err, b)
	}

	// symlink: refused (O_NOFOLLOW)
	link := filepath.Join(dir, "link")
	os.Symlink(p, link)
	if _, err := ReadFileSafe(link, 1<<16); err == nil {
		t.Fatal("symlink accepted")
	}

	// fifo: refused, and must not hang (O_NONBLOCK)
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("no fifos: %v", err)
	}
	if _, err := ReadFileSafe(fifo, 1<<16); err == nil {
		t.Fatal("fifo accepted")
	}

	// hardlink: refused (nlink != 1) — only meaningful on filesystems
	// where hardlinks survive; /run tmpfs does, so this is the real
	// production case.
	hard := filepath.Join(dir, "hard")
	if err := os.Link(p, hard); err != nil {
		t.Skipf("hardlink refused by fs: %v", err)
	}
	if _, err := ReadFileSafe(hard, 1<<16); err == nil {
		t.Fatal("hardlink accepted")
	}

	// oversized: refused
	big := filepath.Join(dir, "big")
	os.WriteFile(big, make([]byte, 100), 0o644)
	if _, err := ReadFileSafe(big, 50); err == nil {
		t.Fatal("oversized file accepted")
	}
}
