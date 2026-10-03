package gateway

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Identity is the kernel/sshd-derived key identity (§5). The displayed
// key ID comes from the root-owned keys.map; the fingerprint comes from
// sshd's ExposeAuthInfo file, read first thing in the gateway before
// any child could tamper with it. Identity is never agent-claimed.
type Identity struct {
	Fingerprint string // "SHA256:…" or "unknown"
	KeyID       string // keys.map label, "unmapped", or "unknown"
	Source      string // $SSH_USER_AUTH path or "none"
}

// ReadIdentity reads $SSH_USER_AUTH and maps the fingerprint to a key
// id via keys.map. All failures degrade to "unknown" identity rather
// than blocking exec — attribution gaps are visible in events and
// flagged by doctor, and ExposeAuthInfo misconfiguration is the
// operator's signal to fix, not a reason to break the agent channel.
func ReadIdentity(getenv func(string) string, readFile func(string) ([]byte, error), keysMapPath string) Identity {
	id := Identity{Fingerprint: "unknown", KeyID: "unknown", Source: "none"}

	path := getenv("SSH_USER_AUTH")
	if path == "" {
		return id
	}
	id.Source = path

	data, err := readFile(path)
	if err != nil || len(data) > 65536 {
		return id
	}
	// Format (sshd ExposeAuthInfo): one line per method,
	//   publickey <authorized-keys-style public key line>
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "publickey ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "publickey "))
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rest)); err == nil {
			id.Fingerprint = ssh.FingerprintSHA256(key)
			break
		}
	}

	if id.Fingerprint == "unknown" {
		return id
	}
	id.KeyID = "unmapped"

	// keys.map: lines of "SHA256:… key-id" (root-owned, 0644).
	km, err := readFile(keysMapPath)
	if err != nil || len(km) > 65536 {
		return id
	}
	for _, line := range strings.Split(string(km), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == id.Fingerprint {
			id.KeyID = fields[1]
			break
		}
	}
	return id
}

// ParseKeysMap parses a keys.map buffer (fingerprint → key id).
func ParseKeysMap(data []byte) (map[string]string, error) {
	m := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		switch len(fields) {
		case 0:
			continue
		case 2:
			m[fields[0]] = fields[1]
		default:
			return nil, fmt.Errorf("keys.map: bad line %q", line)
		}
	}
	return m, nil
}
