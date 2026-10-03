package policy

import (
	"strings"
	"testing"
)

func lintErrs(t *testing.T, p *Policy, fs FS) []string {
	t.Helper()
	var msgs []string
	for _, f := range Lint(p, fs) {
		if f.Severity == SevError {
			msgs = append(msgs, f.Msg)
		}
	}
	return msgs
}

func hasMsg(msgs []string, sub string) bool {
	for _, m := range msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func stdFS() *memFS {
	return newMemFS().
		addFile("/usr/bin/systemctl", 0o755, 0).
		addFile("/usr/bin/journalctl", 0o755, 0).
		addFile("/usr/bin/curl", 0o755, 0)
}

func TestLintDenylistShells(t *testing.T) {
	for _, shell := range []string{"/bin/bash", "/bin/sh", "/bin/dash", "/usr/bin/python3", "/usr/bin/python3.11", "/usr/bin/perl", "/usr/bin/node", "/usr/bin/awk"} {
		p := pol(ModeEnforcing, Rule{Argv: []string{shell}, Path: shell})
		fs := stdFS().addFile(shell, 0o755, 0)
		if msgs := lintErrs(t, p, fs); !hasMsg(msgs, "denylist") {
			t.Errorf("linter did not deny %s: %v", shell, msgs)
		}
	}
}

func TestLintDenylistAliases(t *testing.T) {
	// view is vim's readonly alias — must be caught
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/view", "/etc/sysh/policy.toml"}, Path: "/usr/bin/view"})
	fs := stdFS().addFile("/usr/bin/view", 0o755, 0)
	if msgs := lintErrs(t, p, fs); !hasMsg(msgs, "denylist") {
		t.Errorf("view (vim alias) not denied: %v", msgs)
	}
	// busybox wraps everything
	p2 := pol(ModeEnforcing, Rule{Argv: []string{"/bin/busybox", "ls"}, Path: "/bin/busybox"})
	fs2 := stdFS().addFile("/bin/busybox", 0o755, 0)
	if msgs := lintErrs(t, p2, fs2); !hasMsg(msgs, "denylist") {
		t.Errorf("busybox not denied: %v", msgs)
	}
}

func TestLintSystemctlUserDeniedButPlainAllowed(t *testing.T) {
	// systemctl --user is persistence; plain systemctl is the canonical allowed tool
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/systemctl", "--user", "list-units"}, Path: "/usr/bin/systemctl"})
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "denylist") {
		t.Errorf("systemctl --user not denied: %v", msgs)
	}
	p2 := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/systemctl", "status", "nginx"}, Path: "/usr/bin/systemctl"})
	if msgs := lintErrs(t, p2, stdFS()); hasMsg(msgs, "denylist") {
		t.Errorf("plain systemctl wrongly denied: %v", msgs)
	}
}

func TestLintNetToolsWarningAck(t *testing.T) {
	// curl without ack → warning; with ack → info only
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/curl", "-fsSL", "https://example.com"}, Path: "/usr/bin/curl"})
	warnings := 0
	for _, f := range Lint(p, stdFS()) {
		if f.Severity == SevWarning && strings.Contains(f.Msg, "acknowledge") {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("expected unacknowledged curl warning, got %d: %+v", warnings, Lint(p, stdFS()))
	}

	p2 := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/curl", "-fsSL", "https://example.com"}, Path: "/usr/bin/curl", Ack: true})
	for _, f := range Lint(p2, stdFS()) {
		if f.Severity == SevError || f.Severity == SevWarning {
			t.Fatalf("acked curl rule must not produce warnings: %+v", f)
		}
	}
}

func TestLintPathChecks(t *testing.T) {
	// world-writable binary
	p := pol(ModeEnforcing, Rule{Argv: []string{"/opt/tool/run"}, Path: "/opt/tool/run"})
	fs := newMemFS().addFile("/opt/tool/run", 0o777, 0)
	if msgs := lintErrs(t, p, fs); !hasMsg(msgs, "group/world-writable") {
		t.Errorf("world-writable binary not rejected: %v", msgs)
	}
	// non-root-owned binary
	fs2 := newMemFS().addFile("/opt/tool/run", 0o755, 1000)
	if msgs := lintErrs(t, p, fs2); !hasMsg(msgs, "not owned by root") {
		t.Errorf("non-root binary not rejected: %v", msgs)
	}
	// world-writable ancestor
	fs3 := newMemFS().addDir("/opt", 0o777, 0).addFile("/opt/tool/run", 0o755, 0)
	if msgs := lintErrs(t, p, fs3); !hasMsg(msgs, "group/world-writable") {
		t.Errorf("world-writable ancestor not rejected: %v", msgs)
	}
	// relative path
	p2 := pol(ModeEnforcing, Rule{Argv: []string{"systemctl", "status"}, Path: "systemctl"})
	if msgs := lintErrs(t, p2, stdFS()); !hasMsg(msgs, "absolute") {
		t.Errorf("relative path not rejected: %v", msgs)
	}
}

func TestLintPrivilegedTimeout(t *testing.T) {
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/systemctl", "restart", "nginx"}, Path: "/usr/bin/systemctl", Privileged: true})
	found := false
	for _, f := range Lint(p, stdFS()) {
		if f.Severity == SevWarning && strings.Contains(f.Msg, "timeout") {
			found = true
		}
	}
	if !found {
		t.Error("privileged rule without timeout should warn")
	}
}

func TestLintPermissiveModeNoted(t *testing.T) {
	p := pol(ModePermissive)
	found := false
	for _, f := range Lint(p, stdFS()) {
		if f.Severity == SevInfo && strings.Contains(f.Msg, "disposable") {
			found = true
		}
	}
	if !found {
		t.Error("permissive mode must carry the disposable-host note (info: the hard requirement is the auditd gate at install time, not a warning the ack system cannot express)")
	}
}

func TestLintDuplicateRules(t *testing.T) {
	r := Rule{Argv: []string{"/usr/bin/systemctl", "status", "nginx"}, Path: "/usr/bin/systemctl"}
	p := pol(ModeEnforcing, r, r)
	found := false
	for _, f := range Lint(p, stdFS()) {
		if f.Severity == SevWarning && strings.Contains(f.Msg, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Error("duplicate rules should warn")
	}
}

func TestParseRoundTrip(t *testing.T) {
	doc := `
version = 2
host = "web01"
mode = "enforcing"

[[rule]]
argv = ["/usr/bin/systemctl", "status", "[a-z-]+"]
path = "/usr/bin/systemctl"
timeout = 30

[[rule]]
argv = ["find"]
deny = true

[[rule]]
argv = ["/usr/bin/journalctl", "-u"]
path = "/usr/bin/journalctl"
rest = "[a-z0-9@._\\-]+"
`
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 2 || p.Host != "web01" || p.Mode != ModeEnforcing {
		t.Fatalf("bad parse: %+v", p)
	}
	if len(p.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(p.Rules))
	}
	if !p.Rules[1].Deny {
		t.Error("rule 1 should be deny")
	}
	if p.Rules[0].Timeout != 30 {
		t.Error("timeout not parsed")
	}
	if p.Rules[2].Rest == "" {
		t.Error("rest not parsed")
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		`version = 1`,                                           // wrong version
		`version = 2
mode = "yolo"`, // bad mode
		`version = 2
[[rule]]
path = "/usr/bin/x"`, // empty argv
		`version = 2
[[rule]]
argv = ["/x"]
timeout = 99999`, // out of range
	}
	for _, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("Parse accepted invalid policy:\n%s", doc)
		}
	}
}
