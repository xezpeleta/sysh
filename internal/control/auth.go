package control

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xezpeleta/sysh/internal/fscheck"
	"golang.org/x/crypto/ssh"
)

// cmdAuth manages agent keys (§4.3, §5).
//
//	sysh auth add [--ttl 7d] — reads one authorized_keys line from stdin:
//	                        restrict [from="…"] <type> <base64> <comment= key id>
//	sysh auth list           — keys.map + authorized_keys cross-check
//	sysh auth remove <id>
//	sysh auth rotate <id> [--ttl 7d] — register a new key (stdin), then
//	                        remove the old one; never locked out mid-rotation
func cmdAuth(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh auth add [--ttl 7d]|list|remove <key-id>|rotate <key-id> [--ttl 7d]")
		return 64
	}
	switch args[0] {
	case "add":
		ttl, rest, err := parseTTLFlag(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
			return 64
		}
		return authAdd(ttl, rest)
	case "list":
		return authList()
	case "remove":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: sysh auth remove <key-id>")
			return 64
		}
		return authRemove(args[1])
	case "rotate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: sysh auth rotate <key-id> [--ttl 7d]  (stdin: the new authorized_keys line)")
			return 64
		}
		ttl, rest, err := parseTTLFlag(args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sysh auth rotate: %v\n", err)
			return 64
		}
		if len(rest) > 0 {
			fmt.Fprintln(os.Stderr, "usage: sysh auth rotate <key-id> [--ttl 7d]")
			return 64
		}
		return authRotate(args[1], ttl)
	}
	fmt.Fprintln(os.Stderr, "usage: sysh auth add [--ttl 7d]|list|remove <key-id>|rotate <key-id> [--ttl 7d]")
	return 64
}

// parseTTLFlag extracts a leading --ttl <duration> from args, returning
// the parsed duration and the remaining args.
func parseTTLFlag(args []string) (time.Duration, []string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] != "--ttl" {
			continue
		}
		if i+1 >= len(args) {
			return 0, nil, fmt.Errorf("--ttl needs a duration (e.g. --ttl 7d, --ttl 48h)")
		}
		d, err := parseTTL(args[i+1])
		if err != nil {
			return 0, nil, err
		}
		if d <= 0 {
			return 0, nil, fmt.Errorf("--ttl must be positive")
		}
		rest := append(append([]string{}, args[:i]...), args[i+2:]...)
		return d, rest, nil
	}
	return 0, args, nil
}

// parseTTL accepts Go durations ("48h", "30m") plus day units ("7d"),
// which time.ParseDuration does not know.
func parseTTL(v string) (time.Duration, error) {
	if strings.HasSuffix(v, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil || days < 0 {
			return 0, fmt.Errorf("bad --ttl %q (want e.g. 7d or 48h)", v)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("bad --ttl %q (want e.g. 7d or 48h)", v)
	}
	return d, nil
}

// authAdd parses and registers one agent key. The line must carry the
// `restrict` option; only `restrict` and `from=` are accepted (any
// option granting command/pty/forwarding/agent access is refused).
// A --ttl records an expiry in keys.map; the gateway enforces it.
func authAdd(ttl time.Duration, extra []string) int {
	if len(extra) > 0 {
		fmt.Fprintf(os.Stderr, "sysh auth add: unexpected argument %q\n", extra[0])
		return 64
	}
	line, err := readKeyLine(stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	if line == "" {
		fmt.Fprintln(os.Stderr, "sysh auth add: empty input (expected: restrict [from=\"…\"] <type> <base64> <key-id>)")
		return 1
	}
	return registerKey(line, ttl)
}

// registerKey validates and installs one authorized_keys line (the
// shared core of auth add and auth rotate).
func registerKey(line string, ttl time.Duration) int {
	key, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: not a valid authorized_keys line: %v\n", err)
		return 1
	}

	// Option allowlist: restrict (required) + from= only.
	hasRestrict := false
	var from string
	for _, o := range opts {
		switch {
		case o == "restrict":
			hasRestrict = true
		case strings.HasPrefix(o, "from="):
			from = o
		default:
			fmt.Fprintf(os.Stderr, "sysh auth add: refusing option %q (only restrict and from= are accepted)\n", o)
			return 1
		}
	}
	if !hasRestrict {
		fmt.Fprintln(os.Stderr, "sysh auth add: key line must carry the restrict option")
		return 1
	}

	fingerprint := ssh.FingerprintSHA256(key)

	// Key id: the key comment, or a prompt on the terminal.
	keyID := strings.TrimSpace(comment)
	if keyID == "" {
		keyID = promptKeyID()
		if keyID == "" {
			fmt.Fprintln(os.Stderr, "sysh auth add: no key id (add a comment to the key, or run interactively)")
			return 1
		}
	}
	if !validKeyID(keyID) {
		fmt.Fprintf(os.Stderr, "sysh auth add: invalid key id %q (allowed: letters, digits, @ . _ - /, 1..64 chars)\n", keyID)
		return 1
	}

	// Refuse host directories we do not fully control.
	if err := fscheck.EnsureOwnedDir(etcDir, ownerUID); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}

	// Idempotency: a known fingerprint is never re-registered.
	km, _ := readKeysMap()
	if prev, ok := km[fingerprint]; ok {
		fmt.Fprintf(os.Stderr, "sysh auth add: key already registered as %q; remove it first\n", prev.ID)
		return 1
	}

	// Canonical line: restrict[,from] type base64 comment.
	// authorized_keys options are comma-separated — OpenSSH's parser
	// accepts `restrict from=…` visually but then fails to bind the key
	// (verified live against Debian 12 sshd 9.2).
	canon := strings.TrimRight(string(ssh.MarshalAuthorizedKey(key)), "\n")
	entry := "restrict"
	if from != "" {
		entry += "," + from
	}
	entry += " " + canon

	if err := appendLine(authKeysPath, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	kmLine := fingerprint + " " + keyID
	if ttl > 0 {
		kmLine += " expires:" + nowFn().Add(ttl).UTC().Format(time.RFC3339)
	}
	if err := appendLine(keysMapPath, kmLine); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	if ttl > 0 {
		fmt.Printf("registered %s  fingerprint=%s  expires in %s\n", keyID, fingerprint, ttl)
	} else {
		fmt.Printf("registered %s  fingerprint=%s\n", keyID, fingerprint)
	}
	return 0
}

// authRotate registers the new key read from stdin (same rules as
// auth add) and then removes the old one — add first, remove second,
// so a failure never leaves the host without a working agent key.
func authRotate(oldID string, ttl time.Duration) int {
	line, err := readKeyLine(stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth rotate: %v\n", err)
		return 1
	}
	if line == "" {
		fmt.Fprintln(os.Stderr, "sysh auth rotate: empty input (expected: restrict [from=\"…\"] <type> <base64> <key-id>)")
		return 1
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth rotate: not a valid authorized_keys line: %v\n", err)
		return 1
	}
	newFP := ssh.FingerprintSHA256(key)

	km, err := readKeysMap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth rotate: %v\n", err)
		return 1
	}
	if old, ok := km[newFP]; ok && old.ID == oldID {
		fmt.Fprintf(os.Stderr, "sysh auth rotate: stdin holds the same key as %q — rotation needs fresh key material\n", oldID)
		return 1
	}

	if rc := registerKey(line, ttl); rc != 0 {
		return rc
	}
	if rc := authRemove(oldID); rc != 0 {
		fmt.Fprintf(os.Stderr, "sysh auth rotate: new key registered, but removing %q failed — remove it by hand\n", oldID)
		return rc
	}
	fmt.Printf("rotated %s -> see registered line above\n", oldID)
	return 0
}

func authList() int {
	km, err := readKeysMap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth list: %v\n", err)
		return 1
	}
	if len(km) == 0 {
		fmt.Println("no keys registered")
		return 0
	}
	// Cross-check against authorized_keys by parsing each line and
	// comparing fingerprints (the file holds key material, not
	// fingerprints — substring matching never worked).
	present := map[string]bool{}
	data, _ := os.ReadFile(authKeysPath)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if fp := lineFingerprint(line); fp != "" {
			present[fp] = true
		}
	}
	for fp, e := range km {
		state := "MISSING from authorized_keys"
		if present[fp] {
			state = "ok"
		}
		ttl := "-"
		if !e.Expires.IsZero() {
			if e.Expires.Before(nowFn()) {
				ttl = "EXPIRED " + e.Expires.UTC().Format("2006-01-02")
			} else {
				ttl = "expires " + e.Expires.UTC().Format("2006-01-02")
			}
		}
		fmt.Printf("%-40s %s\n", fp, e.ID+"\t"+ttl+"\t"+state)
	}
	return 0
}

func authRemove(keyID string) int {
	km, err := readKeysMap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth remove: %v\n", err)
		return 1
	}
	var fp string
	found := false
	for f, e := range km {
		if e.ID == keyID {
			fp, found = f, true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "sysh auth remove: no key registered as %q\n", keyID)
		return 1
	}

	// Rewrite keys.map without the entry (expiry fields preserved).
	var out strings.Builder
	for f, e := range km {
		if f != fp {
			line := f + " " + e.ID
			if !e.Expires.IsZero() {
				line += " expires:" + e.Expires.UTC().Format(time.RFC3339)
			}
			fmt.Fprintln(&out, line)
		}
	}
	if err := atomicWrite(keysMapPath, []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth remove: %v\n", err)
		return 1
	}

	// Remove the matching authorized_keys line by fingerprint: the
	// file holds raw key material, not fingerprints, so each line must
	// be parsed and hashed to find the match.
	var kept []string
	data, _ := os.ReadFile(authKeysPath)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if lineFingerprint(line) == fp {
			continue
		}
		kept = append(kept, line)
	}
	var akOut strings.Builder
	for _, l := range kept {
		fmt.Fprintln(&akOut, l)
	}
	if err := atomicWrite(authKeysPath, []byte(akOut.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth remove: %v\n", err)
		return 1
	}
	fmt.Printf("removed %s (%s)\n", keyID, fp)
	return 0
}

// readKeyLine reads the first non-empty line, size-capped, rejecting
// embedded newlines inside the payload (single line by construction).
func readKeyLine(r io.Reader) (string, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 8192))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func promptKeyID() string {
	// Prompt on the controlling terminal (stdin holds the key line).
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ""
	}
	defer tty.Close()
	fmt.Fprint(tty, "key id (e.g. sysh-agent/host): ")
	sc := bufio.NewScanner(tty)
	if !sc.Scan() {
		return ""
	}
	return strings.TrimSpace(sc.Text())
}

func validKeyID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '@', r == '.', r == '_', r == '-', r == '/':
		default:
			return false
		}
	}
	return true
}

// lineFingerprint parses one authorized_keys line and returns its
// SHA256 fingerprint, or "" if the line holds no parseable key.
func lineFingerprint(line string) string {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// keyEntry is one keys.map line: fingerprint → id + optional expiry.
type keyEntry struct {
	ID      string
	Expires time.Time // zero = no TTL
}

func readKeysMap() (map[string]keyEntry, error) {
	data, err := os.ReadFile(keysMapPath)
	if os.IsNotExist(err) {
		return map[string]keyEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	km := map[string]keyEntry{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 {
			continue
		}
		e := keyEntry{ID: fields[1]}
		if len(fields) == 3 && strings.HasPrefix(fields[2], "expires:") {
			if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(fields[2], "expires:")); err == nil {
				e.Expires = t
			}
		}
		km[fields[0]] = e
	}
	return km, nil
}

func appendLine(path, line string) error {
	data, _ := os.ReadFile(path)
	out := string(data)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += line + "\n"
	return atomicWrite(path, []byte(out), 0o644)
}
