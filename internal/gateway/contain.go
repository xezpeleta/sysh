package gateway

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Containment (§6.7). PR_SET_NO_NEW_PRIVS is per-thread in Linux, and
// the Go runtime migrates goroutines between threads, so the bit is set
// on the current thread and the process re-execs itself: execve
// preserves NNP, and the re-exec'd process starts with a single thread
// carrying the bit, which all later threads inherit. The env marker is
// not trusted: after the re-exec the gateway verifies
// NoNewPrivs: 1 in /proc/self/status and fails closed otherwise.
const nnpEnv = "SYSH_NNP_DONE"

// EnsureNNP re-execs the process with NNP set if it has not been done.
// It must be called before any child is spawned.
func EnsureNNP() error {
	if os.Getenv(nnpEnv) == "1" {
		return verifyNNP()
	}
	if err := prSetNoNewPrivs(); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	os.Setenv(nnpEnv, "1")
	argv := append([]string{os.Args[0]}, os.Args[1:]...)
	return syscall.Exec(os.Args[0], argv, os.Environ())
}

func prSetNoNewPrivs() error {
	_, _, errno := syscall.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// verifyNNP fails closed unless the kernel confirms the bit is set.
func verifyNNP() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
			if v == "1" {
				return nil
			}
			return fmt.Errorf("NoNewPrivs is %s, expected 1", v)
		}
	}
	return fmt.Errorf("NoNewPrivs not reported by kernel")
}

// NNPCheck exposes verifyNNP for the startup self-check.
var NNPCheck = verifyNNP

// SetDumpable clears PR_SET_DUMPABLE (§6.7): same-UID processes cannot
// ptrace the gateway or write its /proc/<pid>/mem. Children re-enable
// dumpable on exec.
func SetDumpable() error {
	_, _, errno := syscall.Syscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// Hardening applied to the gateway and inherited by children.
func ApplyResourceLimits() error {
	// No core dumps.
	if err := setRlimit(unix.RLIMIT_CORE, 0, 0); err != nil {
		return err
	}
	// Bounded file descriptors.
	if err := setRlimit(unix.RLIMIT_NOFILE, 512, 512); err != nil {
		return err
	}
	// Best-effort process cap (the scope's TasksMax is the scoped limit).
	_ = setRlimit(unix.RLIMIT_NPROC, 512, 512)
	return nil
}

func setRlimit(res int, cur, max uint64) error {
	limit := unix.Rlimit{Cur: cur, Max: max}
	return unix.Setrlimit(res, &limit)
}

// Umask0077 sets the restrictive umask inherited by children.
func Umask0077() { syscall.Umask(0o077) }

// UserBusAvailable reports whether the user manager's bus socket exists
// (a precondition for systemd-run --user; doctor does the deep checks).
func UserBusAvailable(getenv func(string) string) bool {
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return false
	}
	fi, err := os.Stat(dir + "/bus")
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// SanitizeUnit reduces a key id to [a-z0-9-] for unit names.
func SanitizeUnit(keyID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(keyID) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "agent"
	}
	return s
}
