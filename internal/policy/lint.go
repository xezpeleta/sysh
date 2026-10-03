package policy

import (
	"fmt"
	"os"
	"path/filepath"
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
	Stat(path string) (os.FileInfo, error)      // follows symlinks (realpath check base)
	Lstat(path string) (os.FileInfo, error)
	EvalSymlinks(path string) (string, error)
}

type realFS struct{}

func (realFS) Stat(p string) (os.FileInfo, error)      { return os.Stat(p) }
func (realFS) Lstat(p string) (os.FileInfo, error)     { return os.Lstat(p) }
func (realFS) EvalSymlinks(p string) (string, error)   { return filepath.EvalSymlinks(p) }

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

	hasPrivileged := false
	seen := map[string]int{}

	for i := range p.Rules {
		r := &p.Rules[i]

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
				findings = append(findings, Finding{SevError, i, fmt.Sprintf("argv %q: pattern can match a leading '-' (option injection)", pos)})
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
			if r.Timeout == 0 {
				findings = append(findings, Finding{SevWarning, i, "privileged rule without explicit timeout"})
			}
		}

		// Duplicate detection.
		key := fmt.Sprintf("%v|%s|%v", r.Argv, r.Path, r.Deny)
		if prev, dup := seen[key]; dup {
			findings = append(findings, Finding{SevWarning, i, fmt.Sprintf("duplicate of rule %d", prev)})
		} else {
			seen[key] = i
		}
	}

	if hasPrivileged {
		findings = append(findings, Finding{SevInfo, -1, "policy contains privileged rules; they require human approval (phase 2) and never execute from the agent"})
	}
	if p.Mode == ModePermissive {
		findings = append(findings, Finding{SevWarning, -1, "permissive mode: every well-formed argv runs as the unprivileged sy user — treat the host as disposable and keep auditd active"})
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
