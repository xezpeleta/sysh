package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xezpeleta/sysh/internal/policy"
	"golang.org/x/crypto/ssh"
)

// ---- fixture environment ------------------------------------------------

// newTestEnv points the control package's state at a per-test fixture
// under the user cache dir (never /tmp: the ancestor checks must not
// see a world-writable path) and stubs the host-coupled hooks. It
// restores production defaults on cleanup.
func newTestEnv(t *testing.T) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(cache, "sysh-control-tests", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(base, "etc", "sysh")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}

	saved := struct {
		etcDir, authKeysPath, keysMapPath, policyPath, flagsDir, tripwirePath string
		sudoersPath                                                           string
		ownerUID                                                              int
		stdin                                                                 io.Reader
		lintFS                                                                policy.FS
		auditRulesActiveFn                                                    func() bool
		sudoAvailableFn                                                       func() bool
		visudoCheckFn                                                         func(string) error
		addGroupFn, delGroupFn                                                func(string, string) error
	}{etcDir, authKeysPath, keysMapPath, policyPath, flagsDir, tripwirePath, sudoersPath,
		ownerUID, stdin, lintFS, auditRulesActiveFn, sudoAvailableFn, visudoCheckFn, addGroupFn, delGroupFn}

	t.Cleanup(func() {
		etcDir, authKeysPath, keysMapPath, policyPath, flagsDir, tripwirePath =
			saved.etcDir, saved.authKeysPath, saved.keysMapPath, saved.policyPath, saved.flagsDir, saved.tripwirePath
		sudoersPath = saved.sudoersPath
		ownerUID = saved.ownerUID
		stdin = saved.stdin
		lintFS = saved.lintFS
		auditRulesActiveFn = saved.auditRulesActiveFn
		sudoAvailableFn = saved.sudoAvailableFn
		visudoCheckFn = saved.visudoCheckFn
		addGroupFn, delGroupFn = saved.addGroupFn, saved.delGroupFn
		os.RemoveAll(base)
	})

	etcDir = etc
	authKeysPath = filepath.Join(etc, "authorized_keys")
	keysMapPath = filepath.Join(etc, "keys.map")
	policyPath = filepath.Join(etc, "policy.toml")
	flagsDir = filepath.Join(etc, "flags")
	tripwirePath = filepath.Join(base, "run", "sysh-tripwire", "lockdown")
	sudoersPath = filepath.Join(base, "etc", "sudoers.d", "60-sysh")
	ownerUID = os.Getuid()
	stdin = strings.NewReader("")
	lintFS = newFakeFS()
	auditRulesActiveFn = func() bool { return false }
	sudoAvailableFn = func() bool { return false }
	visudoCheckFn = func(string) error { return nil }
	addGroupFn = func(string, string) error { return nil }
	delGroupFn = func(string, string) error { return nil }

	return base
}

// genKeyLine generates a fresh ed25519 key and returns an
// authorized_keys line for it plus the expected fingerprint.
func genKeyLine(t *testing.T, opts, keyID string) (line, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimRight(string(ssh.MarshalAuthorizedKey(key)), "\n")
	return opts + " " + base + " " + keyID, ssh.FingerprintSHA256(key)
}

func setStdin(s string) { stdin = strings.NewReader(s) }

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ---- fake linter FS -----------------------------------------------------

type fakeFS struct {
	entries map[string]fakeFI
}

type fakeFI struct {
	name string
	mode os.FileMode
	uid  int
}

func (f fakeFI) Name() string       { return filepath.Base(f.name) }
func (f fakeFI) Size() int64        { return 4096 }
func (f fakeFI) Mode() os.FileMode  { return f.mode }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFI) Sys() any {
	st := &syscall.Stat_t{}
	st.Uid = uint32(f.uid)
	return st
}

func newFakeFS() *fakeFS {
	return &fakeFS{entries: map[string]fakeFI{
		"/":    {name: "/", mode: os.ModeDir | 0o755, uid: 0},
		"/usr": {name: "/usr", mode: os.ModeDir | 0o755, uid: 0},
		"/bin": {name: "/bin", mode: os.ModeDir | 0o755, uid: 0},
	}}
}

func (m *fakeFS) addDir(p string, mode os.FileMode, uid int) *fakeFS {
	m.entries[p] = fakeFI{name: p, mode: os.ModeDir | mode, uid: uid}
	return m
}

func (m *fakeFS) addFile(p string, mode os.FileMode, uid int) *fakeFS {
	m.entries[p] = fakeFI{name: p, mode: mode, uid: uid}
	return m
}

func (m *fakeFS) Stat(p string) (os.FileInfo, error) {
	if fi, ok := m.entries[p]; ok {
		return fi, nil
	}
	return nil, &os.PathError{Op: "stat", Path: p, Err: os.ErrNotExist}
}

func (m *fakeFS) Lstat(p string) (os.FileInfo, error) { return m.Stat(p) }

func (m *fakeFS) EvalSymlinks(p string) (string, error) {
	if _, ok := m.entries[p]; ok {
		return p, nil
	}
	return "", &os.PathError{Op: "realpath", Path: p, Err: os.ErrNotExist}
}

// ---- auth ---------------------------------------------------------------

// The canonical authorized_keys line must be comma-separated — this is
// the bug the unifi e2e caught (space-separated options parse visually
// but the key never binds).
func TestAuthAddCanonicalLine(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0)

	line, fp := genKeyLine(t, `restrict,from="10.0.0.0/8"`, "agent/one")
	setStdin(line)

	if rc := cmdAuth([]string{"add"}); rc != 0 {
		t.Fatalf("auth add rc = %d, want 0", rc)
	}

	ak := readFile(t, authKeysPath)
	parts := strings.Fields(ak)
	if len(parts) != 3 {
		t.Fatalf("authorized_keys line = %q, want 3 fields (options, type, base64)", ak)
	}
	if parts[0] != `restrict,from="10.0.0.0/8"` {
		t.Fatalf("options field = %q, want comma-separated restrict,from", parts[0])
	}
	if !strings.HasPrefix(parts[1], "ssh-ed25519") {
		t.Fatalf("key type = %q", parts[1])
	}

	km := readFile(t, keysMapPath)
	if km != fp+" agent/one\n" {
		t.Fatalf("keys.map = %q, want %q", km, fp+" agent/one\n")
	}
}

func TestAuthAddRefusals(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"no restrict", ""},
		{"forbidden option pty", ""},
		{"forbidden option command", ""},
		{"garbage", "this is not a key"},
	}
	// generate real key lines and mangle options per case
	base, _ := genKeyLine(t, "restrict", "x")
	fields := strings.Fields(base)
	// base = restrict ssh-ed25519 AAAA... x  (4 fields incl comment)
	cases[0].line = strings.Join(fields[1:], " ") // no options
	cases[1].line = "restrict,pty " + strings.Join(fields[1:2], " ") + " " + fields[2]
	cases[2].line = `restrict,command="/bin/evil" ` + fields[1] + " " + fields[2]

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newTestEnv(t)
			setStdin(tc.line)
			if rc := cmdAuth([]string{"add"}); rc != 1 {
				t.Fatalf("rc = %d, want 1 (refusal)", rc)
			}
			if _, err := os.Stat(authKeysPath); !os.IsNotExist(err) {
				t.Fatal("authorized_keys must not be written on refusal")
			}
		})
	}
}

func TestAuthAddDuplicateFingerprint(t *testing.T) {
	newTestEnv(t)
	line, _ := genKeyLine(t, "restrict", "first")

	setStdin(line)
	if rc := cmdAuth([]string{"add"}); rc != 0 {
		t.Fatalf("first add rc = %d", rc)
	}
	// same key, different id and options
	fields := strings.Fields(line)
	setStdin("restrict,from=\"10.0.0.0/8\" " + fields[1] + " " + fields[2] + " second")
	if rc := cmdAuth([]string{"add"}); rc != 1 {
		t.Fatalf("duplicate rc = %d, want 1", rc)
	}
	if n := strings.Count(readFile(t, authKeysPath), "\n"); n != 1 {
		t.Fatalf("authorized_keys has %d lines, want 1", n)
	}
}

func TestAuthAddInvalidKeyID(t *testing.T) {
	newTestEnv(t)
	for _, id := range []string{"bad id with spaces", "bad;id", ""} {
		line, _ := genKeyLine(t, "restrict", id)
		setStdin(line)
		if rc := cmdAuth([]string{"add"}); rc != 1 {
			t.Fatalf("key id %q: rc = %d, want 1", id, rc)
		}
	}
	// empty id with no tty prompt available → refusal
}

func TestAuthLifecycle(t *testing.T) {
	newTestEnv(t)
	line, fp := genKeyLine(t, "restrict", "agent/lifecycle")
	setStdin(line)
	if rc := cmdAuth([]string{"add"}); rc != 0 {
		t.Fatalf("add rc = %d", rc)
	}

	if rc := cmdAuth([]string{"list"}); rc != 0 {
		t.Fatalf("list rc = %d", rc)
	}

	if rc := cmdAuth([]string{"remove", "agent/lifecycle"}); rc != 0 {
		t.Fatalf("remove rc = %d", rc)
	}
	if readFile(t, authKeysPath) != "" {
		t.Fatal("authorized_keys not emptied")
	}
	if readFile(t, keysMapPath) != "" {
		t.Fatal("keys.map not emptied")
	}

	// unknown id
	if rc := cmdAuth([]string{"remove", "ghost"}); rc != 1 {
		t.Fatalf("remove unknown rc = %d, want 1", rc)
	}

	// re-add after removal works (fingerprint freed)
	setStdin(line)
	if rc := cmdAuth([]string{"add"}); rc != 0 {
		t.Fatalf("re-add rc = %d", rc)
	}
	if readFile(t, keysMapPath) != fp+" agent/lifecycle\n" {
		t.Fatal("re-add did not restore keys.map entry")
	}
}

// ---- policy -------------------------------------------------------------

const goodPolicy = `version = 2
host = "test"
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/uptime"]
path = "/usr/bin/uptime"
timeout = 15
`

func TestPolicyInstallValid(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0)

	setStdin(goodPolicy)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("install rc = %d, want 0", rc)
	}
	if got := readFile(t, policyPath); got != goodPolicy {
		t.Fatalf("policy file content mismatch:\n%q", got)
	}
	fi, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("policy mode = %o, want 644", fi.Mode().Perm())
	}
}

func TestPolicyInstallRefusesBad(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0).
		addFile("/bin/busybox", 0o755, 0)

	// install a good policy first
	setStdin(goodPolicy)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("initial install rc = %d", rc)
	}

	bad := strings.Replace(goodPolicy,
		`argv = ["/usr/bin/uptime"]
path = "/usr/bin/uptime"`,
		`argv = ["/bin/busybox", "sh"]
path = "/bin/busybox"`, 1)

	setStdin(bad)
	if rc := cmdPolicy([]string{"install"}); rc != 1 {
		t.Fatalf("denylisted install rc = %d, want 1", rc)
	}
	// previous policy must be untouched (atomic install or nothing)
	if readFile(t, policyPath) != goodPolicy {
		t.Fatal("failed install corrupted the previous policy")
	}
}

func TestPolicyInstallWarnAck(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/curl", 0o755, 0)

	curlRule := `version = 2
host = "test"
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/curl", "-fsSL"]
path = "/usr/bin/curl"
rest = "https://[a-z0-9][a-z0-9./_\\-]*"
timeout = 60
%s
`
	setStdin(fmt.Sprintf(curlRule, ""))
	if rc := cmdPolicy([]string{"install"}); rc != 1 {
		t.Fatalf("unacked curl rc = %d, want 1", rc)
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Fatal("policy must not be installed on unacked warning")
	}

	setStdin(fmt.Sprintf(curlRule, "ack = true"))
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("acked curl rc = %d, want 0", rc)
	}
}

func TestPolicyPermissiveGate(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0)

	permissive := strings.Replace(goodPolicy, `mode = "enforcing"`, `mode = "permissive"`, 1)

	auditRulesActiveFn = func() bool { return false }
	setStdin(permissive)
	if rc := cmdPolicy([]string{"install"}); rc != 1 {
		t.Fatal("permissive without auditd rules must be refused")
	}

	auditRulesActiveFn = func() bool { return true }
	setStdin(permissive)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatal("permissive with auditd rules must install (the mode note is informational; auditd is the gate)")
	}
}

func TestPolicyLintSubcommand(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0)

	setStdin(goodPolicy)
	if rc := cmdPolicy([]string{"lint"}); rc != 0 {
		t.Fatalf("lint rc = %d, want 0", rc)
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Fatal("lint must not install")
	}
}

// ---- lockdown -----------------------------------------------------------

func TestLockdown(t *testing.T) {
	base := newTestEnv(t)
	trip := filepath.Join(base, "trip")
	tripwirePath = trip

	if rc := cmdLockdown([]string{"status"}); rc != 0 {
		t.Fatalf("status clear rc = %d", rc)
	}
	os.WriteFile(trip, nil, 0o644)
	if rc := cmdLockdown([]string{"status"}); rc != 0 {
		t.Fatalf("status active rc = %d", rc)
	}
	if rc := cmdLockdown([]string{"clear"}); rc != 0 {
		t.Fatalf("clear rc = %d", rc)
	}
	if _, err := os.Stat(trip); !os.IsNotExist(err) {
		t.Fatal("tripwire flag not removed")
	}
	// clearing an absent flag is fine
	if rc := cmdLockdown([]string{"clear"}); rc != 0 {
		t.Fatalf("clear absent rc = %d", rc)
	}
}

// ---- journal-group ------------------------------------------------------

func TestJournalGroup(t *testing.T) {
	newTestEnv(t)

	if rc := cmdJournalGroup([]string{"enable"}); rc != 0 {
		t.Fatalf("enable rc = %d", rc)
	}
	flag := readFile(t, flagsDir+"/journal-group")
	if flag != "opt-in\n" {
		t.Fatalf("flag content = %q", flag)
	}

	// gpasswd failure → refusal, flag not silently kept as success
	addGroupFn = func(string, string) error { return errors.New("boom") }
	if rc := cmdJournalGroup([]string{"enable"}); rc != 1 {
		t.Fatalf("enable with gpasswd failure rc = %d, want 1", rc)
	}

	if rc := cmdJournalGroup([]string{"disable"}); rc != 0 {
		t.Fatalf("disable rc = %d", rc)
	}
	if _, err := os.Stat(flagsDir + "/journal-group"); !os.IsNotExist(err) {
		t.Fatal("flag not removed on disable")
	}
}

// ---- dispatch / util ----------------------------------------------------

func TestMainRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; refusal path not reachable")
	}
	newTestEnv(t)
	if rc := Main([]string{"auth", "list"}); rc != 1 {
		t.Fatalf("non-root control rc = %d, want 1", rc)
	}
}

func TestAtomicWrite(t *testing.T) {
	newTestEnv(t)
	p := filepath.Join(etcDir, "f")

	if err := atomicWrite(p, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "one" {
		t.Fatal("content mismatch")
	}
	if err := atomicWrite(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "two" {
		t.Fatal("overwrite mismatch")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	// no temp litter
	entries, _ := os.ReadDir(etcDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sysh-tmp-") {
			t.Fatalf("temp file litter: %s", e.Name())
		}
	}
}

func TestPolicyInstallPrivilegedGrant(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/systemctl", 0o755, 0)
	sudoAvailableFn = func() bool { return true }
	visudoCheckFn = func(content string) error {
		if !strings.Contains(content, "NOPASSWD: /usr/bin/systemctl restart nginx") {
			return fmt.Errorf("grant missing from fragment:\n%s", content)
		}
		return nil
	}

	priv := `version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "nginx"]
path = "/usr/bin/systemctl"
privileged = true
ack = true
timeout = 60
`
	setStdin(priv)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("install rc = %d, want 0", rc)
	}
	got := readFile(t, sudoersPath)
	if !strings.Contains(got, "sy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx") {
		t.Fatalf("fragment grant wrong:\n%s", got)
	}
	if !strings.Contains(got, "!setenv") {
		t.Fatalf("fragment must deny env passthrough:\n%s", got)
	}
	fi, err := os.Stat(sudoersPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o440 {
		t.Fatalf("fragment mode = %o, want 0440", fi.Mode().Perm())
	}
}

func TestPolicyInstallPrivilegedNoSudo(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/systemctl", 0o755, 0)
	sudoAvailableFn = func() bool { return false }

	priv := `version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "nginx"]
path = "/usr/bin/systemctl"
privileged = true
ack = true
timeout = 60
`
	setStdin(priv)
	if rc := cmdPolicy([]string{"install"}); rc != 1 {
		t.Fatalf("install rc = %d, want 1", rc)
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Fatal("refused install must not write the policy")
	}
}

func TestPolicyInstallPrivilegedVisudoFail(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/systemctl", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0)
	sudoAvailableFn = func() bool { return true }
	visudoCheckFn = func(string) error { return fmt.Errorf(">>> /etc/sudoers.d/60-sysh: syntax error") }

	// a valid policy first
	setStdin(goodPolicy)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("initial install rc = %d", rc)
	}

	priv := `version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "nginx"]
path = "/usr/bin/systemctl"
privileged = true
ack = true
timeout = 60
`
	setStdin(priv)
	if rc := cmdPolicy([]string{"install"}); rc != 1 {
		t.Fatalf("install rc = %d, want 1", rc)
	}
	// prior policy intact, no fragment
	if readFile(t, policyPath) != goodPolicy {
		t.Fatal("failed privileged install corrupted the previous policy")
	}
	if _, err := os.Stat(sudoersPath); !os.IsNotExist(err) {
		t.Fatal("failed privileged install must not write the fragment")
	}
}

func TestPolicyInstallRemovesStaleGrant(t *testing.T) {
	newTestEnv(t)
	lintFS.(*fakeFS).
		addDir("/usr/bin", 0o755, 0).
		addFile("/usr/bin/systemctl", 0o755, 0).
		addFile("/usr/bin/uptime", 0o755, 0)
	sudoAvailableFn = func() bool { return true }
	visudoCheckFn = func(string) error { return nil }

	priv := `version = 2
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "restart", "nginx"]
path = "/usr/bin/systemctl"
privileged = true
ack = true
timeout = 60
`
	setStdin(priv)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("privileged install rc = %d", rc)
	}
	if _, err := os.Stat(sudoersPath); err != nil {
		t.Fatal("fragment not written")
	}

	// reinstalling a policy without privileged rules must drop the grant
	setStdin(goodPolicy)
	if rc := cmdPolicy([]string{"install"}); rc != 0 {
		t.Fatalf("plain install rc = %d", rc)
	}
	if _, err := os.Stat(sudoersPath); !os.IsNotExist(err) {
		t.Fatal("stale sudoers grant not removed")
	}
}
