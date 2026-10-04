package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSplitCommand(t *testing.T) {
	argv, err := SplitCommand("/usr/bin/systemctl status nginx")
	if err != nil || len(argv) != 3 || argv[0] != "/usr/bin/systemctl" {
		t.Fatalf("basic split failed: %v %v", argv, err)
	}
	// multiple separators produce no empty args (shell-like collapsing
	// is NOT the model; there is simply no way to express an empty arg)
	argv, err = SplitCommand("a \t b  c")
	if err != nil || len(argv) != 3 {
		t.Fatalf("separator collapsing failed: %v %v", argv, err)
	}
	// quotes are ordinary characters — no shell semantics
	if argv, err = SplitCommand(`echo "hello world"`); err != nil || len(argv) != 3 || argv[1] != `"hello` {
		t.Fatalf("quotes must be literal: %v", argv)
	}
}

func TestSplitCommandRejects(t *testing.T) {
	bad := []string{
		"",                         // empty
		"echo \x00hidden",          // NUL byte
		"echo café",                // UTF-8 multibyte
		"echo \x1b[31mred\x1b[0m",  // terminal escape
		"echo \n",                  // newline
		"echo \r",                  // CR
		"echo \x7f",                // DEL
		"echo €",                   // non-ASCII
		strings.Repeat("a", 65537), // too long
	}
	for _, cmd := range bad {
		if _, err := SplitCommand(cmd); err == nil {
			t.Errorf("SplitCommand accepted %#q", cmd)
		}
	}
	// too many args
	var parts []string
	for i := 0; i < 257; i++ {
		parts = append(parts, "x")
	}
	if _, err := SplitCommand(strings.Join(parts, " ")); err == nil {
		t.Error("256+ args must be rejected")
	}
}

func TestSplitCommandLeadingDashIsData(t *testing.T) {
	// a dash-prefixed arg is a valid argv element (options exist);
	// policies simply must not be able to match them with patterns
	argv, err := SplitCommand("/usr/bin/journalctl -u nginx")
	if err != nil || argv[1] != "-u" {
		t.Fatalf("dash arg mishandled: %v %v", argv, err)
	}
}

// genKeyLine generates a fresh ed25519 key and returns the
// authorized_keys-style line and its SHA256 fingerprint.
func genKeyLine(t *testing.T, comment string) (line, fingerprint string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub.Marshal())
	line = fmt.Sprintf("restrict ssh-ed25519 %s %s", b64, comment)
	return line, ssh.FingerprintSHA256(pub)
}

func TestReadIdentity(t *testing.T) {
	line, fp := genKeyLine(t, "test-agent/web01")

	authFile := t.TempDir() + "/user_auth"
	if err := writeTestFile(authFile, "publickey "+line+"\n"); err != nil {
		t.Fatal(err)
	}
	keysMap := t.TempDir() + "/keys.map"
	if err := writeTestFile(keysMap, fp+" test-agent/web01\n"); err != nil {
		t.Fatal(err)
	}

	getenv := func(k string) string {
		if k == "SSH_USER_AUTH" {
			return authFile
		}
		return ""
	}
	readFile := func(p string) ([]byte, error) { return testReadFile(p) }

	id := ReadIdentity(getenv, readFile, keysMap)
	if id.Fingerprint != fp || id.KeyID != "test-agent/web01" {
		t.Fatalf("identity mismatch: %+v (want fp=%s id=test-agent/web01)", id, fp)
	}

	// unknown fingerprint → unmapped
	id = ReadIdentity(getenv, readFile, keysMap+".missing")
	if id.Fingerprint != fp || id.KeyID != "unmapped" {
		t.Fatalf("unmapped identity mishandled: %+v", id)
	}

	// no ExposeAuthInfo → unknown, but exec proceeds (attribution gap)
	id = ReadIdentity(func(string) string { return "" }, readFile, keysMap)
	if id.Fingerprint != "unknown" || id.KeyID != "unknown" {
		t.Fatalf("no-authfile identity mishandled: %+v", id)
	}

	// garbage auth file → unknown, no crash
	if err := writeTestFile(authFile, "garbage not a key\n"); err != nil {
		t.Fatal(err)
	}
	id = ReadIdentity(getenv, readFile, keysMap)
	if id.Fingerprint != "unknown" {
		t.Fatalf("garbage authfile mishandled: %+v", id)
	}
}

func TestReadIdentityExpiry(t *testing.T) {
	line, fp := genKeyLine(t, "test-agent/ttl")

	authFile := t.TempDir() + "/user_auth"
	if err := writeTestFile(authFile, "publickey "+line+"\n"); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "SSH_USER_AUTH" {
			return authFile
		}
		return ""
	}
	readFile := func(p string) ([]byte, error) { return testReadFile(p) }

	exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	keysMap := t.TempDir() + "/keys.map"
	if err := writeTestFile(keysMap, fp+" test-agent/ttl expires:"+exp.Format(time.RFC3339)+"\n"); err != nil {
		t.Fatal(err)
	}
	id := ReadIdentity(getenv, readFile, keysMap)
	if id.KeyID != "test-agent/ttl" || !id.Expires.Equal(exp) {
		t.Fatalf("expiry not read: %+v (want %v)", id, exp)
	}

	// malformed expiry is ignored (cannot widen access), id still maps
	if err := writeTestFile(keysMap, fp+" test-agent/ttl expires:not-a-date\n"); err != nil {
		t.Fatal(err)
	}
	id = ReadIdentity(getenv, readFile, keysMap)
	if id.KeyID != "test-agent/ttl" || !id.Expires.IsZero() {
		t.Fatalf("malformed expiry mishandled: %+v", id)
	}

	if _, err := ParseKeysMap([]byte(fp + " a expires:not-a-date\n")); err == nil {
		t.Fatal("ParseKeysMap must reject a malformed expiry")
	}
	if m, err := ParseKeysMap([]byte(fp + " a expires:" + exp.Format(time.RFC3339) + "\n")); err != nil || m[fp] != "a" {
		t.Fatalf("ParseKeysMap v2 line: %v %v", m, err)
	}
}
