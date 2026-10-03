// Package fscheck verifies that directories sysh writes into are
// root-owned and not group/world-writable, so control-plane writes can
// never land in attacker-controlled paths.
package fscheck

import (
	"fmt"
	"os"
	"syscall"
)

// EnsureOwnedDir verifies dir and every ancestor up to / are owned by
// ownerUID and not group/world-writable, and that dir is a directory.
func EnsureOwnedDir(dir string, ownerUID int) error {
	cur := dir
	for {
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("%s: %w", cur, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", cur)
		}
		if statUID(fi) != ownerUID {
			return fmt.Errorf("%s: owner uid %d, expected %d", cur, statUID(fi), ownerUID)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: group/world-writable (mode %o)", cur, fi.Mode().Perm())
		}
		if cur == "/" {
			return nil
		}
		cur = parentDir(cur)
	}
}

func parentDir(p string) string {
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}

func statUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
