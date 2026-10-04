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

	// 3. Sign: PIN + touch happen inside ssh-keygen, operator's terminal.
	key := keyOverride
	if key == "" && hf.Approver != nil {
		key = hf.Approver.Key
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "sy approve: no approver key configured (hosts.toml [approver] key = …, or -k <path>)")
		return 1
	}
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

	// 4. Submit; the server verifies and executes, printing the outcome.
	return sshExec(hc.Address, []string{"sysh", "approve", id, "--sig"}, bytes.NewReader(sig), nil)
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
