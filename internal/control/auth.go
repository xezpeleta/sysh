package control

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xezpeleta/sysh/internal/fscheck"
	"golang.org/x/crypto/ssh"
)

// cmdAuth manages agent keys (§4.3, §5).
//
//   sysh auth add        — reads one authorized_keys line from stdin:
//                           restrict [from="…"] <type> <base64> <comment= key id>
//   sysh auth list       — keys.map + authorized_keys cross-check
//   sysh auth remove <id>
func cmdAuth(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh auth add|list|remove <key-id>")
		return 64
	}
	switch args[0] {
	case "add":
		return authAdd()
	case "list":
		return authList()
	case "remove":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: sysh auth remove <key-id>")
			return 64
		}
		return authRemove(args[1])
	}
	fmt.Fprintln(os.Stderr, "usage: sysh auth add|list|remove <key-id>")
	return 64
}

// authAdd parses and registers one agent key. The line must carry the
// `restrict` option; only `restrict` and `from=` are accepted (any
// option granting command/pty/forwarding/agent access is refused).
func authAdd() int {
	line, err := readKeyLine(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	if line == "" {
		fmt.Fprintln(os.Stderr, "sysh auth add: empty input (expected: restrict [from=\"…\"] <type> <base64> <key-id>)")
		return 1
	}

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
	if err := fscheck.EnsureOwnedDir(etcDir, 0); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}

	// Idempotency: a known fingerprint is never re-registered.
	km, _ := readKeysMap()
	if prev, ok := km[fingerprint]; ok {
		fmt.Fprintf(os.Stderr, "sysh auth add: key already registered as %q; remove it first\n", prev)
		return 1
	}

	// Canonical line: restrict [from] type base64 comment.
	canon := strings.TrimRight(string(ssh.MarshalAuthorizedKey(key)), "\n")
	entry := "restrict"
	if from != "" {
		entry += " " + from
	}
	entry += " " + canon

	if err := appendLine(authKeysPath, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	if err := appendLine(keysMapPath, fingerprint+" "+keyID); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth add: %v\n", err)
		return 1
	}
	fmt.Printf("registered %s  fingerprint=%s\n", keyID, fingerprint)
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
	// Cross-check against authorized_keys.
	ak, _ := os.ReadFile(authKeysPath)
	for fp, id := range km {
		state := "MISSING from authorized_keys"
		if strings.Contains(string(ak), strings.TrimPrefix(fp, "SHA256:")) || strings.Contains(string(ak), fp) {
			state = "ok"
		}
		fmt.Printf("%-40s %s\n", fp, id+"\t"+state)
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
	for f, id := range km {
		if id == keyID {
			fp, found = f, true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "sysh auth remove: no key registered as %q\n", keyID)
		return 1
	}

	// Rewrite keys.map without the entry.
	var out strings.Builder
	for f, id := range km {
		if f != fp {
			fmt.Fprintf(&out, "%s %s\n", f, id)
		}
	}
	if err := atomicWrite(keysMapPath, []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh auth remove: %v\n", err)
		return 1
	}

	// Remove the matching authorized_keys line (match by fingerprint body).
	body := strings.TrimPrefix(fp, "SHA256:")
	var kept []string
	data, _ := os.ReadFile(authKeysPath)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || !strings.Contains(line, body) {
			if line != "" {
				kept = append(kept, line)
			}
			continue
		}
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
func readKeyLine(r *os.File) (string, error) {
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

func readKeysMap() (map[string]string, error) {
	data, err := os.ReadFile(keysMapPath)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	km := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			km[fields[0]] = fields[1]
		}
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
