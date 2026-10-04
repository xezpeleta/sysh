package policy

import (
	"os"
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

func setuidFS() *memFS {
	return stdFS().addFile("/usr/bin/fakesetuid", os.ModeSetuid|0o755, 0)
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

func TestLintPrivilegedGuardrails(t *testing.T) {
	base := Rule{Argv: []string{"/usr/bin/systemctl", "restart", "nginx"}, Path: "/usr/bin/systemctl", Privileged: true, Ack: true, Timeout: 60}

	// timeout is now mandatory, not a warning
	p := pol(ModeEnforcing, base)
	base.Timeout = 0
	p = pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "explicit timeout") {
		t.Errorf("privileged without timeout must error: %v", msgs)
	}
	base.Timeout = 60

	// ack required
	base.Ack = false
	p = pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "ack = true") {
		t.Errorf("privileged without ack must error: %v", msgs)
	}
	base.Ack = true

	// rest forbidden
	base.Rest = "[a-z]+"
	p = pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "cannot use rest") {
		t.Errorf("privileged with rest must error: %v", msgs)
	}
	base.Rest = ""

	// whitespace in argv elements forbidden
	base.Argv = []string{"/usr/bin/systemctl", "restart", "two words"}
	p = pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "whitespace") {
		t.Errorf("privileged with whitespace argv must error: %v", msgs)
	}
	base.Argv = []string{"/usr/bin/systemctl", "restart", "nginx"}

	// permissive + privileged refused
	p = pol(ModePermissive, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "root-equivalent") {
		t.Errorf("permissive+privileged must error: %v", msgs)
	}

	// valid privileged rule lints clean of errors
	p = pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); msgs != nil {
		t.Errorf("valid privileged rule must not error: %v", msgs)
	}
}

func TestLintPrivilegedSetuidConflict(t *testing.T) {
	priv := Rule{Argv: []string{"/usr/bin/systemctl", "restart", "nginx"}, Path: "/usr/bin/systemctl", Privileged: true, Ack: true, Timeout: 60}
	setuid := Rule{Argv: []string{"/usr/bin/fakesetuid", "/data"}, Path: "/usr/bin/fakesetuid"}
	p := pol(ModeEnforcing, priv, setuid)
	if msgs := lintErrs(t, p, setuidFS()); !hasMsg(msgs, "setuid") {
		t.Errorf("setuid allow-rule with privileged rules present must error: %v", msgs)
	}
	// without privileged rules the same setuid rule is fine (NNP covers it)
	p2 := pol(ModeEnforcing, setuid)
	if msgs := lintErrs(t, p2, setuidFS()); msgs != nil {
		t.Errorf("setuid allow-rule without privileged rules must pass: %v", msgs)
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
		`version = 1`, // wrong version
		`version = 2
mode = "yolo"`, // bad mode
		`version = 2
[[rule]]
path = "/usr/bin/x"`, // empty argv
		`version = 2
[[rule]]
argv = ["/x"]
timeout = 99999`, // out of range
		`version = 2
mode = "enforcing"
nope = true`, // unknown top-level field
		`version = 2
[[rule]]
argv = ["/x"]
path = "/usr/bin/x"
aproval = true`, // unknown rule field (typo of approval)
	}
	for _, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("Parse accepted invalid policy:\n%s", doc)
		} else if !strings.Contains(err.Error(), "unknown field") && strings.Contains(doc, "nope") {
			t.Errorf("Parse error should name the unknown field: %v", err)
		}
	}
}

func TestLintPrivilegedPatternRefused(t *testing.T) {
	base := Rule{Argv: []string{"/usr/bin/tee", "/etc/apache2/sites-available/[a-z]+\\.conf"}, Path: "/usr/bin/tee", Privileged: true, Ack: true, Timeout: 30}
	p := pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "is a pattern (sudoers grants are exact argv") {
		t.Errorf("privileged pattern argv must error: %v", msgs)
	}
}

func TestLintApprovalRules(t *testing.T) {
	base := Rule{Argv: []string{"/usr/bin/systemctl", "restart", "[a-z][a-z0-9\\-]*"}, Path: "/usr/bin/systemctl", Privileged: true, Approval: true, Timeout: 30}

	// a pattern approval rule is valid: no standing grant exists, the
	// approver re-checks the argv and types the pattern-chosen values
	p := pol(ModeEnforcing, base)
	if msgs := lintErrs(t, p, stdFS()); msgs != nil {
		t.Errorf("valid approval rule must not error: %v", msgs)
	}

	// approval without privileged is a schema error
	b := base
	b.Privileged = false
	p = pol(ModeEnforcing, b)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "approval = true requires privileged") {
		t.Errorf("approval without privileged must error: %v", msgs)
	}

	// timeout still mandatory (bounds the root-side execution)
	b = base
	b.Timeout = 0
	p = pol(ModeEnforcing, b)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "approval rule requires an explicit timeout") {
		t.Errorf("approval without timeout must error: %v", msgs)
	}

	// rest is allowed on approval rules (the approver types every
	// rest-chosen argument)
	b = base
	b.Rest = "[a-z0-9\\-]+"
	p = pol(ModeEnforcing, b)
	if msgs := lintErrs(t, p, stdFS()); hasMsg(msgs, "cannot use rest") {
		t.Errorf("approval rule with rest must not error: %v", msgs)
	}

	// permissive + approval refused (root work needs the record)
	p = pol(ModePermissive, base)
	if msgs := lintErrs(t, p, stdFS()); !hasMsg(msgs, "root-equivalent") {
		t.Errorf("permissive+approval must error: %v", msgs)
	}

	// ack is NOT required on approval rules: the per-exec human
	// approval supersedes the install-time acknowledgment
	b = base
	b.Ack = false
	p = pol(ModeEnforcing, b)
	if msgs := lintErrs(t, p, stdFS()); hasMsg(msgs, "ack = true") {
		t.Errorf("approval rule must not demand ack: %v", msgs)
	}

	// approval-only policies keep NoNewPrivs: no setuid conflict
	fs := setuidFS()
	b = base
	p = pol(ModeEnforcing, b)
	if msgs := lintErrs(t, p, fs); hasMsg(msgs, "is setuid while") {
		t.Errorf("approval-only policy must not trigger the NNP setuid scan: %v", msgs)
	}
}
