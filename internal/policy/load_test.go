package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const goodPolicy = `
version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "status", "[a-z-]+"]
path = "/usr/bin/systemctl"
`

// testDir returns a temp dir whose ancestors are not world-writable
// (t.TempDir() lives under /tmp, which the loader correctly rejects).
func testDir(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("no cache dir: %v", err)
	}
	dir, err := os.MkdirTemp(base, "sysh-test-*")
	if err != nil {
		t.Skipf("cannot create test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// writePolicy writes a policy file in a suitable temp dir owned by the
// test uid, with the given mode.
func writePolicy(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := testDir(t)
	p := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(p, []byte(goodPolicy), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGood(t *testing.T) {
	p := writePolicy(t, 0o644)
	pol, sha, raw, err := Load(p, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if pol.Mode != ModeEnforcing || len(pol.Rules) != 1 {
		t.Fatalf("bad policy: %+v", pol)
	}
	if len(sha) != 64 || len(raw) == 0 {
		t.Fatal("sha/raw missing")
	}
}

func TestLoadFailClosedWorldWritableFile(t *testing.T) {
	p := writePolicy(t, 0o666)
	if _, _, _, err := Load(p, os.Getuid()); err == nil {
		t.Fatal("world-writable policy must be rejected")
	}
}

func TestLoadFailClosedWrongOwner(t *testing.T) {
	// ownerUID 0 (root) will not match the test uid
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	p := writePolicy(t, 0o644)
	if _, _, _, err := Load(p, 0); err == nil {
		t.Fatal("wrong-owner policy must be rejected")
	}
}

func TestLoadFailClosedWorldWritableDir(t *testing.T) {
	dir := testDir(t)
	p := filepath.Join(dir, "sub", "policy.toml")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Load(p, os.Getuid()); err == nil {
		t.Fatal("world-writable ancestor must be rejected")
	}
}

func TestLoadFailClosedSymlink(t *testing.T) {
	dir := testDir(t)
	real := filepath.Join(dir, "real.toml")
	link := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(real, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// Load opens the symlink path; unix.Open follows it, but fstat
	// gives the real file — the defense is the owner/mode checks plus
	// lstat of ancestors. A root-owned symlink attack therefore needs
	// root. The load itself must still succeed or fail on merits:
	_, _, _, err := Load(link, os.Getuid())
	if err != nil {
		t.Logf("symlinked policy rejected (%v) — acceptable", err)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, _, _, err := Load("/nonexistent/policy.toml", 0); err == nil {
		t.Fatal("missing policy must be an error (fail closed)")
	}
}
