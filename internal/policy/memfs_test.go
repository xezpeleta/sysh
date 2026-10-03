package policy

import (
	"os"
	"path"
	"syscall"
	"time"
)

// memFS is an in-memory FS for linter tests.
type memFI struct {
	name string
	mode os.FileMode
	uid  int
}

func (m memFI) Name() string       { return path.Base(m.name) }
func (m memFI) Size() int64        { return 1024 }
func (m memFI) Mode() os.FileMode  { return m.mode }
func (m memFI) ModTime() time.Time { return time.Time{} }
func (m memFI) IsDir() bool        { return m.mode.IsDir() }
func (m memFI) Sys() any {
	st := &syscall.Stat_t{}
	st.Uid = uint32(m.uid)
	return st
}

type memFS struct {
	entries map[string]memFI
}

func newMemFS() *memFS {
	return &memFS{entries: map[string]memFI{
		"/": {name: "/", mode: os.ModeDir | 0o755, uid: 0},
	}}
}

func (m *memFS) addDir(p string, mode os.FileMode, uid int) *memFS {
	m.entries[p] = memFI{name: p, mode: os.ModeDir | mode, uid: uid}
	return m
}

func (m *memFS) addFile(p string, mode os.FileMode, uid int) *memFS {
	m.entries[p] = memFI{name: p, mode: mode, uid: uid}
	return m
}

func (m *memFS) Stat(p string) (os.FileInfo, error)    { return m.get(p) }
func (m *memFS) Lstat(p string) (os.FileInfo, error)   { return m.get(p) }
func (m *memFS) EvalSymlinks(p string) (string, error) { return p, nil }

// get returns the explicit entry, or synthesizes a default root-owned
// 0755 parent directory (so tests only declare interesting paths).
func (m *memFS) get(p string) (os.FileInfo, error) {
	if fi, ok := m.entries[p]; ok {
		return fi, nil
	}
	if p == "/" {
		return m.entries["/"], nil
	}
	// synthesized ancestor
	return memFI{name: p, mode: os.ModeDir | 0o755, uid: 0}, nil
}
