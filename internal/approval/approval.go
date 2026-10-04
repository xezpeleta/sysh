// Package approval implements the §9 request/result file contract:
// the on-disk protocol between the unprivileged gateway (writer of
// requests) and the root-side approver (reader of requests, writer of
// results). Both sides treat request files as untrusted data — the sy
// UID controls their content, so every field is validated on read and
// nothing is ever interpreted (only displayed, re-checked against the
// root-owned policy, and executed from the approver's own in-memory
// copy).
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Volatile-state layout (§4.5, created by tmpfiles/postinst):
//
//	/run/sysh/requests  root:sy 0730 — drop box: sy may create files,
//	                    cannot list or read others back
//	/run/sysh/results   root:sy 0750 — sy may read result files by name,
//	                    cannot create or modify them
const (
	RequestsDir = "/run/sysh/requests"
	ResultsDir  = "/run/sysh/results"
)

// Bounds (§9.3 request hygiene; §9 result contract).
const (
	RequestTTL      = 10 * time.Minute // requests expire if not approved
	ResultTTL       = time.Hour        // results expire after the fetch window
	MaxRequestFile  = 8 << 10          // 8 KiB: requests are tiny, cap hard
	MaxResultFile   = 256 << 10        // 256 KiB: capped child output + header
	MaxResultStream = 64 << 10         // 64 KiB captured per child stream
	MaxLiveRequests = 5                // approver refuses beyond this
)

// Request is one pending privileged execution, written by the gateway
// (uid sy) into the drop box. All fields are untrusted until the
// approver re-validates them.
type Request struct {
	ID          string    `json:"id"`
	KeyID       string    `json:"key"` // claimed label; the journal carries the kernel-trusted one
	Fingerprint string    `json:"fingerprint"`
	Argv        []string  `json:"argv"`
	Time        time.Time `json:"time"`
}

// Result is the outcome of an approved execution, written root-side;
// the agent fetches it read-only via the sysh-result builtin.
type Result struct {
	ID         string    `json:"id"`
	Argv       []string  `json:"argv"`
	Exit       int       `json:"exit"`
	DurationMS int64     `json:"duration_ms"`
	Truncated  bool      `json:"truncated"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Time       time.Time `json:"time"`
}

// ID derives a deterministic request id from the argv and requesting
// key: identical live requests dedupe to the same file (§9.3). The id
// is opaque data on both sides.
func ID(argv []string, keyID string) string {
	h := sha256.New()
	for _, a := range argv {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	h.Write([]byte(keyID))
	return "req_" + hex.EncodeToString(h.Sum(nil))[:12]
}

// ValidID reports whether s is a well-formed request id.
func ValidID(s string) bool {
	if !strings.HasPrefix(s, "req_") || len(s) != 4+12 {
		return false
	}
	for _, c := range s[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseRequest validates and decodes a request file body. Strict: the
// JSON must be an object of exactly these fields, argv printable-ASCII
// (the gateway only ever writes such argv; anything else is tampering),
// sizes bounded, id well-formed, timestamps sane.
func ParseRequest(data []byte) (Request, error) {
	var r Request
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("request is not valid JSON: %v", err)
	}
	if dec.More() {
		return r, fmt.Errorf("trailing data after request object")
	}
	if !ValidID(r.ID) {
		return r, fmt.Errorf("malformed request id %q", r.ID)
	}
	if len(r.Argv) == 0 || len(r.Argv) > 64 {
		return r, fmt.Errorf("argv length out of bounds")
	}
	for _, a := range r.Argv {
		if a == "" || len(a) > 256 || !printableASCII(a) {
			return r, fmt.Errorf("argv element not printable ASCII or out of bounds")
		}
	}
	if len(r.KeyID) > 128 || !printableASCII(r.KeyID) {
		return r, fmt.Errorf("key id not printable ASCII or out of bounds")
	}
	if len(r.Fingerprint) > 128 || !printableASCII(r.Fingerprint) {
		return r, fmt.Errorf("fingerprint not printable ASCII or out of bounds")
	}
	// Time sanity: not before 2020, not far in the future. The approver
	// enforces the real TTL; this only rejects garbage.
	if r.Time.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		r.Time.After(time.Now().Add(24*time.Hour)) {
		return r, fmt.Errorf("request timestamp out of sane range")
	}
	return r, nil
}

// ParseResult validates and decodes a result file body. Same
// strictness, defense in depth: the agent cannot write the results
// directory at all.
func ParseResult(data []byte) (Result, error) {
	var r Result
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("result is not valid JSON: %v", err)
	}
	if !ValidID(r.ID) {
		return r, fmt.Errorf("malformed result id %q", r.ID)
	}
	if len(r.Argv) > 64 {
		return r, fmt.Errorf("argv length out of bounds")
	}
	if len(r.Stdout) > MaxResultStream || len(r.Stderr) > MaxResultStream {
		return r, fmt.Errorf("result stream exceeds cap")
	}
	return r, nil
}

// ReadFileSafe opens path under the §9 spool hygiene rules: O_NOFOLLOW
// (a planted symlink must not redirect the reader), O_NONBLOCK (a
// planted FIFO must not hang it), then fstat: regular file, single
// link (not a hardlink planted elsewhere), size-capped. Returns the
// (bounded) body.
func ReadFileSafe(path string, max int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("not a regular file")
	}
	if st.Nlink != 1 {
		return nil, fmt.Errorf("not a single-link file")
	}
	if st.Size > max {
		return nil, fmt.Errorf("file exceeds size cap (%d > %d bytes)", st.Size, max)
	}
	buf := make([]byte, st.Size)
	n, err := unix.Read(fd, buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// RequestPath returns the drop-box path for a request id.
func RequestPath(dir, id string) string { return filepath.Join(dir, id) }

// ResultPath returns the results path for a request id.
func ResultPath(dir, id string) string { return filepath.Join(dir, id) }

// printableASCII reports whether s is entirely printable ASCII
// (0x20–0x7E), matching the gateway's argv grammar.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}
