// Operator approval keys (§9, signed-approval transport): the keys
// whose signatures `sysh approve <id> --sig` accepts. Managed as
// /etc/sysh/approvers/<name>.pub (one bare public key per file,
// root-owned), rendered into an OpenSSH allowed_signers file at
// verify time and checked with stock `ssh-keygen -Y verify` under the
// sysh-approve namespace.
//
//	sysh approver add <name>     — reads one public key line from stdin
//	sysh approver list
//	sysh approver remove <name>
//
// Hardware-backed sk-* keys (FIDO2) add a physical touch per
// signature — malware can hold the key handle but not the token.
// Plain keys are accepted too: authenticity and single-use
// (request-bound, TTL'd) still hold; the touch guarantee does not.
package control

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// approversDir holds one <name>.pub per registered approver.
var approversDir = "/etc/sysh/approvers"

var approverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func cmdApprover(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh approver add|list|remove <name>")
		return 64
	}
	switch args[0] {
	case "add":
		if len(args) != 2 || !approverNameRe.MatchString(args[1]) {
			fmt.Fprintln(os.Stderr, "usage: sysh approver add <name>   (name: [a-z0-9][a-z0-9._-]{0,63})")
			return 64
		}
		return approverAdd(args[1])
	case "list":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: sysh approver list")
			return 64
		}
		return approverList()
	case "remove":
		if len(args) != 2 || !approverNameRe.MatchString(args[1]) {
			fmt.Fprintln(os.Stderr, "usage: sysh approver remove <name>")
			return 64
		}
		return approverRemove(args[1])
	}
	fmt.Fprintln(os.Stderr, "usage: sysh approver add|list|remove <name>")
	return 64
}

// approverAdd registers one public key. The input line is a bare key
// (type, base64, optional comment) — options are refused: an approver
// key is not an agent key, it grants signature verification only.
func approverAdd(name string) int {
	line, err := readKeyLine(stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approver add: %v\n", err)
		return 1
	}
	if line == "" {
		fmt.Fprintln(os.Stderr, "sysh approver add: empty input (expected: <type> <base64> [comment])")
		return 1
	}
	key, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approver add: not a valid public key: %v\n", err)
		return 1
	}
	if len(opts) > 0 {
		fmt.Fprintf(os.Stderr, "sysh approver add: no options expected on an approver key (got %q)\n", strings.Join(opts, ","))
		return 1
	}

	// Normalize: type + base64 + comment, nothing else.
	norm := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if comment != "" {
		norm = norm + " " + comment
	}

	dest := approversDir + "/" + name + ".pub"
	if _, err := os.Stat(dest); err == nil {
		fmt.Fprintf(os.Stderr, "sysh approver add: %s already exists (remove it first)\n", name)
		return 1
	}
	if err := os.MkdirAll(approversDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "sysh approver add: %v\n", err)
		return 1
	}
	if err := os.WriteFile(dest, []byte(norm+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh approver add: %v\n", err)
		return 1
	}
	fmt.Printf("registered approver %s (%s, %s)\n", name, key.Type(), ssh.FingerprintSHA256(key))
	if !strings.HasPrefix(key.Type(), "sk-") {
		fmt.Fprintf(os.Stderr, "note: %s is not hardware-backed; signed approvals from it carry authenticity and single-use, but no per-signature touch (sk-* keys do)\n", key.Type())
	}
	return 0
}

func approverList() int {
	names, err := approverNames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh approver list: %v\n", err)
		return 1
	}
	if len(names) == 0 {
		fmt.Println("no approvers registered (sysh approver add <name>, then feed a public key on stdin)")
		return 0
	}
	for _, n := range names {
		body, err := os.ReadFile(approversDir + "/" + n + ".pub")
		if err != nil {
			fmt.Printf("%s  (unreadable: %v)\n", n, err)
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(body)
		if err != nil {
			fmt.Printf("%s  (invalid: %v)\n", n, err)
			continue
		}
		fmt.Printf("%s  %s  %s\n", n, key.Type(), ssh.FingerprintSHA256(key))
	}
	return 0
}

func approverRemove(name string) int {
	if err := os.Remove(approversDir + "/" + name + ".pub"); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "sysh approver remove: no such approver: %s\n", name)
			return 1
		}
		fmt.Fprintf(os.Stderr, "sysh approver remove: %v\n", err)
		return 1
	}
	fmt.Printf("removed approver %s\n", name)
	return 0
}

// approverNames lists registered approver names (sorted).
func approverNames() ([]string, error) {
	entries, err := os.ReadDir(approversDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, ".pub") || len(n) <= 4 {
			continue
		}
		if !approverNameRe.MatchString(n[:len(n)-4]) {
			continue
		}
		names = append(names, n[:len(n)-4])
	}
	sort.Strings(names)
	return names, nil
}
