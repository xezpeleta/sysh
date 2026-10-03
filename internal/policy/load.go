package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// readFile is a seam for tests.
var readFile = os.ReadFile

// Load loads and parses a policy file with fail-closed filesystem
// checks (§7): open once, fstat the open descriptor (regular file,
// owned by ownerUID, not group/world-writable), verify every ancestor
// directory likewise, then parse that same buffer — no re-open, no
// TOCTOU. Any anomaly is an error and the gateway must deny all exec.
func Load(path string, ownerUID int) (*Policy, string, []byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", nil, fmt.Errorf("policy: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, "", nil, fmt.Errorf("policy: fstat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, "", nil, fmt.Errorf("policy: %s: not a regular file", path)
	}
	if int(st.Uid) != ownerUID {
		return nil, "", nil, fmt.Errorf("policy: %s: owner uid %d, expected %d", path, st.Uid, ownerUID)
	}
	if st.Mode&0o022 != 0 {
		return nil, "", nil, fmt.Errorf("policy: %s: group/world-writable (mode %o)", path, st.Mode&0o777)
	}

	if err := checkAncestors(path, ownerUID); err != nil {
		return nil, "", nil, err
	}

	// Read the whole file through the verified descriptor (size-capped
	// defensively; a policy is a small human-authored document).
	const maxPolicySize = 1 << 20
	if st.Size > maxPolicySize {
		return nil, "", nil, fmt.Errorf("policy: %s: too large (%d bytes)", path, st.Size)
	}
	buf := make([]byte, st.Size)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return nil, "", nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	buf = buf[:n]

	p, err := Parse(buf)
	if err != nil {
		return nil, "", nil, err
	}
	sum := sha256.Sum256(buf)
	return p, hex.EncodeToString(sum[:]), buf, nil
}

// checkAncestors lstats every ancestor of path up to / and requires
// root-style ownership (ownerUID) and no group/world write bit.
func checkAncestors(path string, ownerUID int) error {
	// Collect ancestors from / down to (excluding) the file itself.
	var dirs []string
	cur := path
	for {
		cur = parentOf(cur)
		if cur == "" {
			break
		}
		dirs = append([]string{cur}, dirs...)
		if cur == "/" {
			break
		}
	}
	for _, d := range dirs {
		var st unix.Stat_t
		if err := unix.Lstat(d, &st); err != nil {
			return fmt.Errorf("policy: lstat %s: %w", d, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("policy: %s: ancestor is not a directory", d)
		}
		if int(st.Uid) != ownerUID && st.Uid != 0 {
			return fmt.Errorf("policy: %s: owner uid %d, expected %d or root", d, st.Uid, ownerUID)
		}
		if st.Mode&0o022 != 0 {
			return fmt.Errorf("policy: %s: group/world-writable (mode %o)", d, st.Mode&0o777)
		}
	}
	return nil
}

func parentOf(p string) string {
	// filepath.Dir semantics without importing path/filepath into a
	// security-sensitive path walker; strings only, no symlink games.
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p == "" || p == "/" {
		return ""
	}
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i <= 0 {
		return "/"
	}
	return p[:i]
}
