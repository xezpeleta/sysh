package watch

// ceremony.go — the in-web approval ceremony.
//
// Same rules as the terminal ceremony, restated for the browser:
//
//   - display == signer: the process that shows the argv (this
//     server) is the process that signs the exact bytes it fetched;
//     the browser is only the renderer, the way gnome-terminal is
//     the renderer of `sy approve`.
//   - the argv is fetched from the host at ceremony time (fresh
//     pending fetch + the exact request bytes); it never arrives
//     from the request body.
//   - a typed argument is required before the touch — the modal
//     asks for the LAST argv element, which forces reading the
//     actual command. Wrong typing burns the ceremony (one-shot);
//     starting over means looking at the argv again.
//   - the touch happens inside ssh-keygen, exactly as in the
//     terminal. A PIN-requiring (verify-required) key fails headless
//     with a clear error pointing at the terminal ceremony.
//   - same-origin only: Sec-Fetch-Site + JSON content type are
//     enforced, so visited web pages cannot drive the ceremony
//     (local same-user malware can talk to loopback directly — but
//     it can equally drive `sy approve` through a synthetic TTY;
//     against that adversary the touch is the wall either way).
//
// The server already holds the operator's root SSH channel (it
// follows journals with it), so gaining the ability to sign adds no
// standing power to the process — only this carefully gated surface.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// CeremonyTTL bounds how long a started ceremony may be confirmed.
var CeremonyTTL = 2 * time.Minute

// CeremonyInfo is what the modal shows — fetched fresh at ceremony
// start, never client-supplied.
type CeremonyInfo struct {
	ID     string   `json:"id"`
	Host   string   `json:"host"`
	Key    string   `json:"key"`
	Argv   []string `json:"argv"`
	AgeSec int64    `json:"age_sec"`
	Body   []byte   `json:"-"` // exact request bytes to sign
}

// Ceremony is one started, unconfirmed ceremony.
type Ceremony struct {
	Info    CeremonyInfo
	Token   string
	Prompt  string    // what the operator must type (last argv element)
	Expires time.Time
}

// CeremonyStore holds live ceremonies. One per request id.
type CeremonyStore struct {
	mu    sync.Mutex
	items map[string]*Ceremony // by request id
}

func NewCeremonyStore() *CeremonyStore {
	return &CeremonyStore{items: make(map[string]*Ceremony)}
}

func (s *CeremonyStore) Put(c *Ceremony) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.Info.ID] = c
}

// Take removes and returns the ceremony for id (one-shot: confirming
// or mistyping consumes it). Expired ceremonies return nil.
func (s *CeremonyStore) Take(id, token string) *Ceremony {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return nil
	}
	delete(s.items, id)
	if token == "" || token != c.Token || time.Now().After(c.Expires) {
		return nil
	}
	return c
}

// FetchRequestFunc gathers ceremony info from a host. Seam for tests.
type FetchRequestFunc func(host, addr, id string) (*CeremonyInfo, error)

// SignSubmitFunc signs the request bytes with the operator's approver
// key and submits the signature. Seam for tests.
type SignSubmitFunc func(approverKey, host, addr, id string, body []byte) (string, error)

// newCeremonyToken is a random bearer for one ceremony.
func newCeremonyToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// realFetchRequest fetches the pending snapshot (fresh argv/key/age)
// and the exact request bytes (`sysh approve <id> --show`) over the
// operator's root SSH.
func realFetchRequest(host, addr, id string) (*CeremonyInfo, error) {
	pend, err := realFetchOne(host, addr)
	if err != nil {
		return nil, err
	}
	var found *Pending
	for i := range pend {
		if pend[i].ID == id {
			// An expired request cannot be approved; the ceremony
			// would sign bytes the host will refuse. Fail here, where
			// the modal can say it, instead of at the touch.
			if pend[i].Expired {
				return nil, fmt.Errorf("request %s has expired (refuse-by-default) — the agent can re-file", id)
			}
			found = &pend[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("request %s is not pending on %s", id, host)
	}
	cmd := exec.Command("ssh", append(sshDestArgs(addr), "sysh", "approve", id, "--show")...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("fetch request bytes: %v", err)
	}
	return &CeremonyInfo{
		ID: id, Host: host, Key: found.Key,
		Argv: found.Argv, AgeSec: int64(found.AgeSec),
		Body: bytes.TrimSpace(out.Bytes()),
	}, nil
}

// realSignSubmit signs body with the approver key (the token touch
// happens inside ssh-keygen) and submits the signature to the host.
func realSignSubmit(approverKey, host, addr, id string, body []byte) (string, error) {
	if approverKey == "" {
		return "", fmt.Errorf("no approver key configured (hosts.toml [approver])")
	}
	dir, err := os.MkdirTemp("", "sy-ceremony-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	bodyFile := filepath.Join(dir, "request")
	if err := os.WriteFile(bodyFile, body, 0o600); err != nil {
		return "", err
	}
	_ = os.Remove(bodyFile + ".sig") // never reuse a stale signature

	sign := exec.Command("ssh-keygen", "-Y", "sign", "-f", approverKey, "-n", "sysh-approve", bodyFile)
	var signErr bytes.Buffer
	sign.Stdout = io.Discard
	sign.Stderr = &signErr
	if err := sign.Run(); err != nil {
		msg := signErr.String()
		if bytes.Contains(signErr.Bytes(), []byte("PIN")) || bytes.Contains(signErr.Bytes(), []byte("askpass")) {
			return "", fmt.Errorf("this approver key needs its PIN — use the terminal ceremony (run in terminal / sy approve)")
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("signing failed (no touch?): %s", firstLine(msg))
	}
	sig, err := os.ReadFile(bodyFile + ".sig")
	if err != nil {
		return "", fmt.Errorf("signature file missing: %v", err)
	}
	submit := exec.Command("ssh", append(sshDestArgs(addr), "sysh", "approve", id, "--sig")...)
	submit.Stdin = bytes.NewReader(sig)
	var result bytes.Buffer
	submit.Stdout = &result
	submit.Stderr = &result
	if err := submit.Run(); err != nil {
		return "", fmt.Errorf("submit failed: %s", firstLine(result.String()))
	}
	return result.String(), nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

// RealFetchRequest / RealSignSubmit are the production seams.
var (
	RealFetchRequest FetchRequestFunc = realFetchRequest
	RealSignSubmit   SignSubmitFunc   = realSignSubmit
)
