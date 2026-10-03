package policy

import (
	"os"
	"syscall"
)

// statUID extracts the owner uid from os.FileInfo (Linux).
func statUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
