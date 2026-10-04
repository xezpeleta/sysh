// approve.go — `sy approve` / `sy approvals`: the OPERATOR-side approval
// ceremony (PROJECT.md §9, transport B wrapped). Not an MCP tool, never
// agent-callable: the argv display is fetched from the server through
// the operator's own root SSH channel, and the signing gesture (YubiKey
// PIN + touch with an sk-* key) happens in the operator's terminal.
//
// The trust argument, stated once: the FIDO2 PIN and touch prompts are
// blind — they authorize whatever bytes the invoking process signs. If
// the agent drove this ceremony it could display "rebooting the server"
// while signing "rm -rf /". So the display must come from the server via
// a channel the agent cannot write to (root SSH, operator's key), which
// is what `sysh approve --show` provides; this command only wraps it.
//
// Flow:
//
//	sy approve [host] <request-id> [-k <approver-key>]
//
//	  1. ssh root@host 'sysh approve <id> --show'   (server-recorded bytes)
//	  2. display the argv; recompute the request id locally and refuse
//	     on mismatch
//	  3. ssh-keygen -Y sign -n sysh-approve          (PIN + touch here)
//	  4. ssh root@host 'sysh approve <id> --sig'     (verify + execute)
//
//	sy approvals [host]
//
//	  passthrough listing of pending requests (root channel).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
)

// Seams for tests: the ssh and ssh-keygen subprocess entry points.
var (
	sshExec = realSSHExec
	sshSign = realSSHSign
)

// skProbe reports whether a FIDO2 authenticator is currently attached.
// Preferred: libfido2's fido2-token (any authenticator, from the
// fido2-tools package). Fallback with zero extra dependencies: the
// Yubico USB vendor id in sysfs.
var skProbe = realSkProbe

func realSkProbe() bool {
	if _, err := exec.LookPath("fido2-token"); err == nil {
		out, err := exec.Command("fido2-token", "-L").Output()
		return err == nil && len(bytes.TrimSpace(out)) > 0
	}
	matches, _ := filepath.Glob("/sys/bus/usb/devices/*/idVendor")
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err == nil && strings.TrimSpace(string(b)) == "1050" {
			return true
		}
	}
	return false
}

// insertWait is how long the insert-your-YubiKey loop lasts before
// giving up (nothing signed, request stays pending).
var insertWait = 30 * time.Second

// waitForKeyToken is the insertion loop: ssh-keygen fails outright if
// the token is not attached, so the ceremony asks for it first and
// polls until the operator plugs it in (or the timeout expires).
func waitForKeyToken() bool {
	fmt.Fprintf(os.Stderr, "insert your YubiKey… (waiting up to %s)\n", insertWait)
	deadline := time.Now().Add(insertWait)
	for {
		if skProbe() {
			fmt.Fprintln(os.Stderr, "authenticator detected")
			return true
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "no authenticator within the timeout — nothing was signed")
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// approverIsSkKey reports whether the configured approver key is a
// hardware (sk-*) key, read from its paired .pub file.
func approverIsSkKey(key string) bool {
	b, err := os.ReadFile(key + ".pub")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(b))
	return len(fields) > 0 && strings.HasPrefix(fields[0], "sk-")
}

// confirmGesture is the deliberate pause between the display and the
// signature: with a software (passphrase-less) approver key there is no
// PIN and no touch — the operator reading the box and typing yes is the
// whole ceremony. Refused without a real TTY: automation cannot consent.
var confirmGesture = realConfirmGesture

func realConfirmGesture(req requestBody) bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "sy approve: stdin is not a terminal — the confirmation gesture cannot be skipped; run sy approve interactively")
		return false
	}
	fmt.Print("authorize exactly this? type yes to sign: ")
	var ans string
	if n, err := fmt.Scan(&ans); n != 1 && err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(ans), "yes")
}

// realSSHExec runs `ssh root@<addr> <args…>`; stderr always streams to
// the operator; stdout is captured when out != nil (else it streams).
// stdin, when non-nil, feeds the remote command (--sig submission).
func realSSHExec(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
	full := append([]string{"root@" + addr}, args...)
	cmd := exec.Command("ssh", full...)
	cmd.Stdin = stdin
	if out != nil {
		cmd.Stdout = out
	} else {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "sy: ssh: %v\n", err)
	return 255
}

// realSSHSign signs file with the approver key under the sysh-approve
// namespace. PIN and touch prompts happen here, in the operator's
// terminal — that is the ceremony.
func realSSHSign(key, file string) error {
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", key, "-n", "sysh-approve", file)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// requestBody is the server's request JSON (internal/approval grammar).
type requestBody struct {
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Fingerprint string   `json:"fingerprint"`
	Argv        []string `json:"argv"`
	Time        string   `json:"time"`
}

func usageApprove() {
	fmt.Fprintln(os.Stderr, "usage: sy approve [host] <request-id> [-k <approver-key>]")
}

func cmdApprovalsClient(args []string) int {
	hc, code := resolveOpHost(args)
	if code != 0 {
		return code
	}
	return sshExec(hc.Address, []string{"sysh", "approvals"}, nil, nil)
}

func cmdApproveClient(args []string) int {
	var keyOverride, id, hostName string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-k" || strings.HasPrefix(a, "-k"):
			if keyOverride != "" {
				usageApprove()
				return 64
			}
			if len(a) > 2 {
				keyOverride = a[2:] // attached: -k<path>
			} else if i+1 < len(args) {
				i++
				keyOverride = args[i]
			} else {
				usageApprove()
				return 64
			}
		default:
			if !approval.ValidID(a) {
				if hostName == "" && id == "" {
					hostName = a // first non-flag token: host name
					continue
				}
				fmt.Fprintf(os.Stderr, "sy approve: not a request id: %q (want req_ + 12 hex)\n", a)
				return 64
			}
			if id != "" {
				usageApprove()
				return 64
			}
			id = a
		}
	}
	if id == "" {
		usageApprove()
		return 64
	}
	hf, err := loadHosts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	hc, err := hf.resolveHost(hostName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// 1. Fetch the exact request bytes from the server (root channel).
	var body bytes.Buffer
	if code := sshExec(hc.Address, []string{"sysh", "approve", id, "--show"}, nil, &body); code != 0 {
		return code
	}
	var req requestBody
	if err := json.Unmarshal(body.Bytes(), &req); err != nil {
		fmt.Fprintf(os.Stderr, "sy approve: server returned an unparseable request: %v\n", err)
		return 1
	}
	if req.ID != id {
		fmt.Fprintf(os.Stderr, "sy approve: server returned request %s for id %s — refusing\n", req.ID, id)
		return 1
	}
	// Local consistency: the id must be the content hash of (argv, key).
	// The server re-checks this; doing it here keeps a tampered body from
	// ever reaching the signing gesture.
	if want := approval.ID(req.Argv, req.Key); want != id {
		fmt.Fprintf(os.Stderr, "sy approve: request id does not match its content (tampered?) — refusing\n")
		return 1
	}

	// 2. Display what the touch will authorize. This is the trusted
	// screen: server-recorded argv over the operator's root channel.
	printRequestBox(req)

	// 2.5 The gesture: a deliberate pause after reading the box. With
	// sk-* keys the PIN and touch inside ssh-keygen are the gesture;
	// with software keys this prompt is all there is.
	if !confirmGesture(req) {
		fmt.Fprintln(os.Stderr, "aborted (request stays pending)")
		return 1
	}

	// 3. Resolve the approver key (hosts.toml [approver] or -k).
	key := keyOverride
	if key == "" && hf.Approver != nil {
		key = hf.Approver.Key
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "sy approve: no approver key configured (hosts.toml [approver] key = …, or -k <path>)")
		return 1
	}

	// 4. If the approver key is hardware-bound, ask for the token
	// first and wait for it: ssh-keygen would just fail if unplugged.
	if approverIsSkKey(key) && !waitForKeyToken() {
		fmt.Fprintln(os.Stderr, "aborted (request stays pending)")
		return 1
	}

	// 5. Sign: PIN + touch happen inside ssh-keygen, operator's terminal.
	dir, err := os.MkdirTemp("", "sy-approve-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	bodyFile := filepath.Join(dir, "request")
	if err := os.WriteFile(bodyFile, body.Bytes(), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := sshSign(key, bodyFile); err != nil {
		fmt.Fprintf(os.Stderr, "sy approve: signing failed (nothing was submitted)\n")
		return 1
	}
	sig, err := os.ReadFile(bodyFile + ".sig")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sy approve: signature file missing: %v\n", err)
		return 1
	}

	// 5. Submit; the server verifies and executes, printing the outcome.
	rc := sshExec(hc.Address, []string{"sysh", "approve", id, "--sig"}, bytes.NewReader(sig), nil)
	if rc != 0 {
		fmt.Fprintf(os.Stderr, "sy approve: signed with %s — if the server rejected it, this key is not registered there (sysh approver list, hosts.toml [approver] key, or -k)\n", key)
	}
	return rc
}

// resolveOpHost resolves the optional host argument shared by the
// operator subcommands.
func resolveOpHost(args []string) (*hostConfig, int) {
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: sy approvals [host]")
		return nil, 64
	}
	name := ""
	if len(args) == 1 {
		name = args[0]
	}
	hf, err := loadHosts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, 1
	}
	hc, err := hf.resolveHost(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, 1
	}
	return hc, 0
}

// printRequestBox renders the request the way the gesture will bind it.
func printRequestBox(req requestBody) {
	age := ""
	if t, err := time.Parse(time.RFC3339Nano, req.Time); err == nil {
		age = fmt.Sprintf("  age: %s", time.Since(t).Round(time.Second))
	}
	fmt.Printf("┌─ sysh approval request %s ──────────────\n", req.ID)
	fmt.Printf("│  key: %s (claimed)%s\n", req.Key, age)
	for _, a := range req.Argv {
		fmt.Printf("│  argv: %s\n", a)
	}
	fmt.Printf("└─ sign with your approver key to authorize exactly this ──\n")
}
