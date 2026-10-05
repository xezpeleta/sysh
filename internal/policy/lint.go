package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Finding severities.
const (
	SevError   = 1 // refuse install
	SevWarning = 2 // requires ack = true on the rule
	SevInfo    = 3 // informational
)

// Finding is one linter result.
type Finding struct {
	Severity int
	Rule     int // -1 for policy-level findings
	Msg      string
}

func (f Finding) String() string {
	sev := "ERROR"
	switch f.Severity {
	case SevWarning:
		sev = "WARNING"
	case SevInfo:
		sev = "info"
	}
	if f.Rule >= 0 {
		return fmt.Sprintf("%s rule[%d]: %s", sev, f.Rule, f.Msg)
	}
	return fmt.Sprintf("%s: %s", sev, f.Msg)
}

// FS abstracts filesystem checks for the linter (tests use fakes).
type FS interface {
	Stat(path string) (os.FileInfo, error) // follows symlinks (realpath check base)
	Lstat(path string) (os.FileInfo, error)
	EvalSymlinks(path string) (string, error)
}

type realFS struct{}

func (realFS) Stat(p string) (os.FileInfo, error)    { return os.Stat(p) }
func (realFS) Lstat(p string) (os.FileInfo, error)   { return os.Lstat(p) }
func (realFS) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }

// RealFS returns the real filesystem implementation.
func RealFS() FS { return realFS{} }

// Lint runs the mandatory linter (§7) over a parsed policy.
func Lint(p *Policy, fs FS) []Finding {
	var findings []Finding

	if p.Version != 2 {
		findings = append(findings, Finding{SevError, -1, fmt.Sprintf("version must be 2, got %d", p.Version)})
	}
	if p.Mode == "" {
		findings = append(findings, Finding{SevWarning, -1, "mode not set; defaulting to enforcing"})
	}

	// Agent scripts directory (§6.10): if declared, it must be a
	// root-owned directory with no group/world-write anywhere on the
	// path — the agent owns the files inside, never the directory
	// itself.
	if p.AgentScripts != "" {
		if err := checkAgentScriptsDir(fs, p.AgentScripts); err != nil {
			findings = append(findings, Finding{SevError, -1, err.Error()})
		} else {
			findings = append(findings, Finding{SevInfo, -1,
				"agent_scripts: every line of every script there is policy-checked and journaled like a direct exec"})
		}
		switch m := p.AgentScriptsMode; m {
		case "", AgentModeLines:
			// default: nothing to add
		case AgentModeTraced:
			findings = append(findings, Finding{SevInfo, -1,
				"agent_scripts_mode = traced: interpreters (any shebang) run as the unprivileged gateway user under ptrace; " +
					"every execve in the tree is policy-checked and journaled; what the interpreter reads or writes with builtins " +
					"is NOT argv-visible; traced children get rlimits instead of a systemd scope"})
		default:
			findings = append(findings, Finding{SevError, -1,
				fmt.Sprintf("agent_scripts_mode must be %q or %q (got %q)", AgentModeLines, AgentModeTraced, m)})
		}
	} else if p.AgentScriptsMode != "" {
		findings = append(findings, Finding{SevWarning, -1,
			"agent_scripts_mode set without agent_scripts: ignored"})
	}

	hasPrivileged := false // any privileged rule (standing or approval)
	hasStanding := false   // privileged without per-exec approval: sudoers grant + NNP off
	hasApproval := false
	seen := map[string]int{}

	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Privileged && !r.Deny {
			hasPrivileged = true
			if r.Approval {
				hasApproval = true
			} else {
				hasStanding = true
			}
		}
		if r.Approval && !r.Privileged {
			findings = append(findings, Finding{SevError, i, "approval = true requires privileged = true (approval is the runtime gate on a privileged rule)"})
		}

		// Pattern safety on every position (§6.2).
		for _, pos := range r.Argv {
			info, err := AnalyzePattern(pos)
			if err != nil {
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("argv %q: %v", pos, err)})
				continue
			}
			if info.CanEmpty {
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("argv %q: pattern can match the empty string", pos)})
			}
			if !info.First.Empty() && info.First.Contains('-') {
				// Option injection: a pattern that can match a leading '-'
				// could let unknown options through. In a fixed position the
				// operator wrote the option cluster themselves — allowed, but
				// only with an explicit ack (live-caught: the documented
				// rsync --server transfer rule is impossible without this).
				if r.Ack {
					findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("argv %q: pattern can match a leading '-' — acknowledged option cluster", pos)})
				} else {
					findings = append(findings, Finding{SevError, i, fmt.Sprintf("argv %q: pattern can match a leading '-' (option injection; add ack = true if this position is an option cluster you wrote)", pos)})
				}
			}
			if info.HasAnyChar {
				findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("argv %q: unescaped '.' matches any character; use '\\.' if you mean a literal dot", pos)})
			}
		}
		if r.Rest != "" {
			info, err := AnalyzePattern(r.Rest)
			if err != nil {
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("rest %q: %v", r.Rest, err)})
			} else {
				if info.CanEmpty {
					findings = append(findings, Finding{SevError, i, fmt.Sprintf("rest %q: pattern can match the empty string", r.Rest)})
				}
				if !info.First.Empty() && info.First.Contains('-') {
					findings = append(findings, Finding{SevError, i, fmt.Sprintf("rest %q: pattern can match a leading '-' (option injection)", r.Rest)})
				}
				if info.HasAnyChar {
					findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("rest %q: unescaped '.' matches any character; use '\\.' if you mean a literal dot", r.Rest)})
				}
			}
		}

		if r.Deny {
			if r.Path != "" {
				findings = append(findings, Finding{SevWarning, i, "deny rule carries a path (ignored)"})
			}
			if r.Rest != "" {
				findings = append(findings, Finding{SevWarning, i, "deny rule carries rest (ignored; deny is prefix-semantic)"})
			}
			if r.Privileged {
				findings = append(findings, Finding{SevError, i, "deny rule cannot be privileged"})
			}
		} else {
			if r.Path != "" && !filepath.IsAbs(r.Path) {
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("path %q must be absolute", r.Path)})
			}
			// Path checks (§6.2): absolute, exists, root-owned, and no
			// group/world-writable binary or ancestor.
			if err := checkPath(fs, r.Path); err != nil {
				findings = append(findings, Finding{SevError, i, err.Error()})
			} else {
				// Denylist on realpath + basename (§7).
				real, _ := fs.EvalSymlinks(r.Path)
				base := filepath.Base(real)
				if hit := CheckDenylist(real, base, r.Argv); hit != nil {
					if hit.Warn && r.Ack {
						findings = append(findings, Finding{SevInfo, i, fmt.Sprintf("acknowledged: %s (%s)", hit.Reason, base)})
					} else if hit.Warn {
						findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("%s is a %s — set ack = true on this rule to acknowledge", base, hit.Reason)})
					} else {
						findings = append(findings, Finding{SevError, i, fmt.Sprintf("%s is on the escape-hatch denylist (%s)", base, hit.Reason)})
					}
				}
			}
		}

		if r.Privileged {
			hasPrivileged = true
			if r.Deny {
				findings = append(findings, Finding{SevError, i, "deny rule cannot be privileged"})
			}
			if r.Approval {
				// Approval rules (§9) have no standing sudoers grant —
				// root execution happens only after a per-exec operator
				// approval, and the approver re-checks this rule at that
				// moment. Patterns and rest are therefore representable;
				// the sudoers-exactness guardrails below do not apply.
				if r.Timeout == 0 {
					findings = append(findings, Finding{SevError, i, "approval rule requires an explicit timeout (bounds the root-side execution)"})
				}
				continue
			}
			// Standing privileged rules run via exact-argv sudoers grants;
			// the guardrails below are what make generation safe.
			if r.Rest != "" {
				findings = append(findings, Finding{SevError, i, "privileged rule cannot use rest (sudoers grants are exact argv)"})
			}
			for _, a := range r.Argv {
				if isPattern(a) {
					findings = append(findings, Finding{SevError, i, fmt.Sprintf("privileged rule argv element %q is a pattern (sudoers grants are exact argv; enumerate the literal commands instead)", a)})
				}
			}
			if !r.Ack {
				findings = append(findings, Finding{SevError, i, "privileged rule requires ack = true (deliberate root-exec opt-in)"})
			}
			if r.Timeout == 0 {
				findings = append(findings, Finding{SevError, i, "privileged rule requires an explicit timeout"})
			}
			for _, a := range r.Argv {
				if strings.ContainsAny(a, " \t") {
					findings = append(findings, Finding{SevError, i, fmt.Sprintf("privileged rule argv element %q contains whitespace (unrepresentable in sudoers)", a)})
				}
			}
		}

		// Duplicate detection.
		key := fmt.Sprintf("%v|%s|%v|%v", r.Argv, r.Path, r.Deny, r.Privileged)
		if prev, dup := seen[key]; dup {
			findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("duplicate of rule %d", prev)})
		} else {
			seen[key] = i
		}
	}

	if hasStanding {
		// Without NNP (required so sudo can elevate), a setuid binary
		// allowed by a normal rule would silently grant root — flag it.
		for i := range p.Rules {
			r := &p.Rules[i]
			if r.Deny || r.Privileged || r.Path == "" {
				continue
			}
			if fi, err := fs.Stat(r.Path); err == nil && fi.Mode()&os.ModeSetuid != 0 {
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("path %q is setuid while the policy has privileged rules (NNP is off on this host) — remove the rule or the privileged ones", r.Path)})
			}
		}
		findings = append(findings, Finding{SevInfo, -1, "policy contains privileged rules: they execute as root via exact-argv sudo (generated at install), and the gateway runs without NoNewPrivs on this host"})
	}
	if hasPrivileged && p.Mode == ModePermissive {
		findings = append(findings, Finding{SevError, -1, "permissive mode with privileged rules is root-equivalent; refuse"})
	}
	if hasApproval {
		findings = append(findings, Finding{SevInfo, -1, "policy contains approval rules: root execution happens only after a per-exec operator approval (sysh approvals / sysh approve as root); the gateway itself stays unprivileged"})
	}
	if p.Mode == ModePermissive {
		findings = append(findings, Finding{SevInfo, -1, "permissive mode: every well-formed argv runs as the unprivileged sy user — treat the host as disposable; install refuses it without active auditd rules"})
	}

	// Root mode (§6.9): deny rules only. Every allow/approval construct
	// is meaningless — everything not denied already runs as root.
	if p.Mode == ModeRoot {
		for i := range p.Rules {
			r := &p.Rules[i]
			if r.Deny {
				continue
			}
			if r.Privileged || r.Approval {
				findings = append(findings, Finding{SevError, i, "privileged/approval rule in root mode: everything already runs as root — approval gates nothing; write deny rules only"})
			} else {
				findings = append(findings, Finding{SevError, i, "allow rule in root mode is meaningless — everything not denied already runs as root; write deny rules only"})
			}
		}
		findings = append(findings, Finding{SevInfo, -1, "root mode: every argv not denied runs as root via a wildcard sudoers grant — this is total freedom with a journal, not control; after the first exec the agent can mint access the journal never sees; treat the host as disposable"})
	}

	// ack = true means the operator reviewed THIS rule: its warnings
	// fold to info (they were advisory, and they were read). Errors
	// never fold — ack acknowledges risk, not malformation.
	for idx := range p.Rules {
		if !p.Rules[idx].Ack {
			continue
		}
		for j := range findings {
			f := &findings[j]
			if f.Rule == idx && f.Severity == SevWarning {
				f.Severity = SevInfo
				f.Msg = "acknowledged: " + f.Msg
			}
		}
	}

	return findings
}

// checkPath verifies a rule binary path: exists, resolves to a regular
// file, owned by root, not group/world-writable, and no ancestor
// group/world-writable.
func checkPath(fs FS, path string) error {
	if path == "" {
		return fmt.Errorf("missing path")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path %q must be absolute", path)
	}
	fi, err := fs.Stat(path)
	if err != nil {
		return fmt.Errorf("path %q: %v", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("path %q: not a regular file", path)
	}
	if !ownedByRoot(fi) {
		return fmt.Errorf("path %q: not owned by root", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("path %q: group/world-writable", path)
	}
	// Walk ancestors (realpath so symlinked /bin is checked as /usr/bin).
	real, err := fs.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("path %q: realpath: %v", path, err)
	}
	dir := filepath.Dir(real)
	for {
		di, err := fs.Lstat(dir)
		if err != nil {
			return fmt.Errorf("ancestor %q: %v", dir, err)
		}
		if !di.IsDir() {
			return fmt.Errorf("ancestor %q: not a directory", dir)
		}
		if !ownedByRoot(di) {
			return fmt.Errorf("ancestor %q: not owned by root", dir)
		}
		if di.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("ancestor %q: group/world-writable", dir)
		}
		if dir == "/" {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

func ownedByRoot(fi os.FileInfo) bool {
	return fi.Sys() != nil && statUID(fi) == 0
}

// checkAgentScriptsDir verifies the agent-script directory (§6.10):
// absolute, exists, root-owned, not group/world-writable, and every
// ancestor the same. The files inside may be agent-owned — the
// directory and its path may never be agent-controlled.
func checkAgentScriptsDir(fs FS, dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("agent_scripts %q must be absolute", dir)
	}
	fi, err := fs.Stat(dir)
	if err != nil {
		return fmt.Errorf("agent_scripts %q: %v", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("agent_scripts %q: not a directory", dir)
	}
	if !ownedByRoot(fi) {
		return fmt.Errorf("agent_scripts %q: not owned by root", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("agent_scripts %q: group/world-writable", dir)
	}
	real, err := fs.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("agent_scripts %q: realpath: %v", dir, err)
	}
	d := filepath.Dir(real)
	for {
		di, err := fs.Lstat(d)
		if err != nil {
			return fmt.Errorf("agent_scripts ancestor %q: %v", d, err)
		}
		if !di.IsDir() {
			return fmt.Errorf("agent_scripts ancestor %q: not a directory", d)
		}
		if !ownedByRoot(di) {
			return fmt.Errorf("agent_scripts ancestor %q: not owned by root", d)
		}
		if di.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("agent_scripts ancestor %q: group/world-writable", d)
		}
		if d == "/" {
			break
		}
		d = filepath.Dir(d)
	}
	return nil
}
