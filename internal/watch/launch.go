package watch

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// Launching the ceremony from the web: the browser can open a
// terminal that RUNS "sy approve <host> <id>", but the HTTP surface
// never signs anything. The argv box, the typed confirmation, the
// token gesture — all of it happens in the spawned terminal, driven
// by the operator, exactly as if they had typed the command.

// requestIDRe matches the gateway's request ids (req_%012x).
var requestIDRe = regexp.MustCompile(`^req_[0-9a-f]{12}$`)

// ValidRequestID reports whether id looks like a gateway request id.
func ValidRequestID(id string) bool { return requestIDRe.MatchString(id) }

// LaunchApproveFunc opens a terminal emulator running the approval
// ceremony. Seam for tests.
type LaunchApproveFunc func(host, id string) error

// RealLaunchApprove is the desktop implementation.
var RealLaunchApprove LaunchApproveFunc = realLaunchApprove

// realLaunchApprove finds a terminal emulator on the operator's
// desktop and starts "<self> approve <host> <id>" in it.
func realLaunchApprove(host, id string) error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("no display session: cannot open a terminal — copy the command instead")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve sy path: %v", err)
	}
	child := []string{self, "approve", host, id}

	// emulators that can run a command; $TERMINAL first if set.
	type candidate struct {
		bin  string
		args func(cmd []string) []string
	}
	withDashDash := func(cmd []string) []string { return append([]string{"--"}, cmd...) }
	withE := func(cmd []string) []string { return append([]string{"-e"}, cmd...) }
	withX := func(cmd []string) []string { return append([]string{"-x"}, cmd...) }
	list := []candidate{
		{"gnome-terminal", withDashDash},
		{"konsole", withE},
		{"xfce4-terminal", withX},
		{"kitty", func(cmd []string) []string { return cmd }},
		{"alacritty", withE},
		{"wezterm", withDashDash},
		{"xterm", withE},
	}
	if t := os.Getenv("TERMINAL"); t != "" {
		list = append([]candidate{{t, withE}}, list...)
	}
	var tried []string
	for _, c := range list {
		path, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, c.args(child)...)
		cmd.Env = os.Environ()
		if err := cmd.Start(); err != nil {
			tried = append(tried, c.bin)
			continue
		}
		// Reap when the emulator process eventually exits.
		go func() { _ = cmd.Wait() }()
		return nil
	}
	if len(tried) > 0 {
		return fmt.Errorf("terminal emulators failed to start (%s) — copy the command instead", commaJoin(tried))
	}
	return fmt.Errorf("no terminal emulator found (tried the usual ones) — copy the command instead")
}

func commaJoin(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// launchLimiter caps ceremony launches so a rogue local page can at
// worst pop a handful of terminals, never a storm. The ceremony gates
// (typed confirmation + token touch) are unchanged either way.
var launchLimiter = struct {
	sync.Mutex
	hits []time.Time
}{}

const launchWindow = time.Minute
const launchMax = 5

func launchAllowed() bool {
	launchLimiter.Lock()
	defer launchLimiter.Unlock()
	now := time.Now()
	keep := launchLimiter.hits[:0]
	for _, t := range launchLimiter.hits {
		if now.Sub(t) < launchWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) >= launchMax {
		launchLimiter.hits = keep
		return false
	}
	launchLimiter.hits = append(keep, now)
	return true
}
