package control

import (
	"os"
)

// atomicWrite writes data to path via a same-directory temp file and
// rename (no window with wrong ownership or a partial file). Mode is
// the final file mode; ownership is root:root (control runs as root).
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := parentDir(path)
	tmp, err := os.CreateTemp(dir, ".sysh-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Chown(tmpName, 0, 0); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
