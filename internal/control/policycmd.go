package control

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xezpeleta/sysh/internal/fscheck"
	"github.com/xezpeleta/sysh/internal/policy"
)

// cmdPolicy implements `sysh policy install|lint` (§7).
func cmdPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh policy install [file] | sysh policy lint [file]")
		return 64
	}
	sub, rest := args[0], args[1:]
	if len(rest) > 1 {
		fmt.Fprintln(os.Stderr, "usage: sysh policy install [file]")
		return 64
	}

	var data []byte
	var err error
	source := "stdin"
	if len(rest) == 1 {
		source = rest[0]
		data, err = os.ReadFile(rest[0])
	} else {
		data, err = io.ReadAll(io.LimitReader(stdin, 1<<20))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh policy %s: %v\n", sub, err)
		return 1
	}

	p, perr := policy.Parse(data)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "sysh policy %s: %v\n", sub, perr)
		return 1
	}

	findings := policy.Lint(p, lintFS)
	errors, warnings := reportFindings(findings)
	if errors > 0 {
		fmt.Fprintf(os.Stderr, "sysh policy %s: %d error(s); refusing\n", sub, errors)
		return 1
	}
	if sub == "lint" {
		if warnings == 0 && errors == 0 {
			fmt.Println("policy lint: clean")
		}
		return 0
	}

	// install: warnings require per-rule ack, which Lint already folded
	// into severity (unacknowledged warnings arrive as SevWarning).
	if warnings > 0 {
		fmt.Fprintf(os.Stderr, "sysh policy install: %d unacknowledged warning(s); set ack = true on the rule or fix them\n", warnings)
		return 1
	}

	// Permissive mode requires active auditd rules (§6.6, §8.4).
	if p.Mode == policy.ModePermissive && !auditRulesActiveFn() {
		fmt.Fprintln(os.Stderr, "sysh policy install: permissive mode requires active auditd integration (§8.4);")
		fmt.Fprintln(os.Stderr, "  reinstall the package with auditd present, or verify /etc/audit/rules.d/60-sysh.rules and run augenrules --load")
		return 1
	}

	if err := fscheck.EnsureOwnedDir(etcDir, ownerUID); err != nil {
		fmt.Fprintf(os.Stderr, "sysh policy install: %v\n", err)
		return 1
	}

	// Privileged rules (§6.4): the sudoers grant is generated from the
	// policy — single source of truth, exact argv, validated with
	// visudo before anything is written. All checks happen before the
	// policy is installed: a failed install changes nothing.
	sudoers, hasPriv := buildSudoers(p)
	if n := countApprovalRules(p); n > 0 {
		fmt.Printf("%d approval rule(s): no standing sudoers grant — root execution only after per-exec approval (sysh approvals / sysh approve)\n", n)
	}
	if hasPriv {
		if !sudoAvailableFn() {
			fmt.Fprintln(os.Stderr, "sysh policy install: privileged rules require sudo (apt install sudo) or removing the privileged rules")
			return 1
		}
		if !sudoTimeoutTagFn() {
			fmt.Fprintln(os.Stderr, "sysh policy install: privileged rules require sudo >= 1.9.13 (per-command TIMEOUT; this host's sudo is older) — remove the privileged rules or upgrade sudo")
			return 1
		}
		if err := visudoCheckFn(sudoers); err != nil {
			fmt.Fprintf(os.Stderr, "sysh policy install: sudoers fragment rejected by visudo: %v\n", err)
			return 1
		}
	}

	if err := atomicWrite(policyPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh policy install: %v\n", err)
		return 1
	}

	// Grant written after the policy: if this fails, the direction of
	// failure is safe (privileged argv present, no grant — sudo
	// refuses). Doctor reports the drift.
	if hasPriv {
		if err := os.MkdirAll(filepath.Dir(sudoersPath), 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "sysh policy install: cannot create %s: %v\n", filepath.Dir(sudoersPath), err)
			return 1
		}
		if err := atomicWrite(sudoersPath, []byte(sudoers), 0o440); err != nil {
			fmt.Fprintf(os.Stderr, "sysh policy install: policy installed but sudoers grant not written: %v\n", err)
			fmt.Fprintf(os.Stderr, "  re-run the install to regenerate %s\n", sudoersPath)
			return 1
		}
		fmt.Printf("sudoers grant installed: %d privileged rule(s) as exact-argv root grants (%s)\n", countPrivileged(p), sudoersPath)
	} else if _, err := os.Stat(sudoersPath); err == nil {
		// No privileged rules anymore — remove the stale grant.
		if err := os.Remove(sudoersPath); err != nil {
			fmt.Fprintf(os.Stderr, "sysh policy install: stale sudoers grant %s not removed: %v\n", sudoersPath, err)
			return 1
		}
		fmt.Printf("sudoers grant removed (no privileged rules)\n")
	}

	fmt.Printf("policy installed from %s (mode=%s, %d rules)\n", source, p.Mode, len(p.Rules))
	return 0
}

// buildSudoers renders the /etc/sudoers.d fragment for the policy's
// privileged rules. Each grant is one exact argv line — no wildcards,
// no rest, no env. Returns hasPriv=false when the policy has no
// privileged rules.
func buildSudoers(p *policy.Policy) (string, bool) {
	var b strings.Builder
	hasPriv := false
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Privileged && !r.Deny && !r.Approval {
			// Approval rules (§9) get no standing grant: their root
			// execution happens per-exec from `sysh approve`, not from
			// the gateway through sudo.
			hasPriv = true
			// TIMEOUT (Option_Spec, sudo >= 1.9.13) makes sudo kill
			// its own root child on expiry — the user manager cannot
			// signal root processes, so sudo is the only reliable
			// in-process enforcer. The gateway's timeout remains as
			// the outer backstop for sudo itself.
			fmt.Fprintf(&b, "sy ALL=(root) TIMEOUT=%d NOPASSWD: %s\n", r.Timeout, strings.Join(r.Argv, " "))
		}
	}
	if !hasPriv {
		return "", false
	}
	header := `# Generated by sysh policy install — do not edit by hand.
# Regenerate with: sysh policy install < policy.toml
# Each line is one exact-argv root grant for the sy user.
Defaults:sy !setenv
`
	return header + b.String(), true
}

func countPrivileged(p *policy.Policy) int {
	n := 0
	for i := range p.Rules {
		if p.Rules[i].Privileged && !p.Rules[i].Deny && !p.Rules[i].Approval {
			n++
		}
	}
	return n
}

func countApprovalRules(p *policy.Policy) int {
	n := 0
	for i := range p.Rules {
		if p.Rules[i].Privileged && !p.Rules[i].Deny && p.Rules[i].Approval {
			n++
		}
	}
	return n
}

// sudoAvailable reports whether sudo is installed.
func sudoAvailable() bool {
	_, err := exec.LookPath("sudo")
	return err == nil
}

// sudoTimeoutTag reports whether the installed sudo supports the
// per-command TIMEOUT= option (1.9.13+). The sudoers fragment depends
// on it to enforce privileged timeouts: the user manager cannot signal
// root processes, so sudo must kill its own child.
func sudoTimeoutTag() bool {
	out, err := exec.Command("sudo", "--version").Output()
	if err != nil {
		if out, err = exec.Command("/usr/bin/sudo", "--version").Output(); err != nil {
			return false
		}
	}
	// The version line is localized ("Sudo version x" / "x sudo
	// bertsioa") — find the first version-shaped field instead of
	// trusting a fixed index.
	var major, minor, patch int
	found := false
	for _, f := range strings.Fields(string(out)) {
		if len(f) > 0 && f[0] >= '0' && f[0] <= '9' {
			if _, err := fmt.Sscanf(f, "%d.%d.%d", &major, &minor, &patch); err == nil {
				found = true
			}
			break
		}
	}
	if !found {
		return false
	}
	return major > 1 || (major == 1 && (minor > 9 || (minor == 9 && patch >= 13)))
}

// visudoCheck validates a sudoers fragment with visudo -cf.
func visudoCheck(content string) error {
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		if _, err2 := os.Stat("/usr/sbin/visudo"); err2 == nil {
			visudo = "/usr/sbin/visudo"
		} else {
			return fmt.Errorf("visudo not found (install the sudo package)")
		}
	}
	tmp, err := os.CreateTemp("/etc/sudoers.d", ".sysh-check-*")
	if err != nil {
		// /etc/sudoers.d may be root-only; fall back to a world-readable
		// temp copy — visudo only parses it, permissions of the source
		// are irrelevant to syntax validation.
		tmp, err = os.CreateTemp("", ".sysh-check-*")
		if err != nil {
			return err
		}
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	out, err := exec.Command(visudo, "-cf", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func reportFindings(findings []policy.Finding) (errors, warnings int) {
	for _, f := range findings {
		fmt.Println("  " + f.String())
		switch f.Severity {
		case policy.SevError:
			errors++
		case policy.SevWarning:
			warnings++
		}
	}
	return errors, warnings
}

// auditRulesActive reports whether the sysh-scoped auditd rules are
// loaded in the running kernel.
func auditRulesActive() bool {
	out, err := exec.Command("/usr/sbin/auditctl", "-l").Output()
	if err != nil {
		if out, err = exec.Command("auditctl", "-l").Output(); err != nil {
			return false
		}
	}
	return strings.Contains(strings.ToLower(string(out)), "sysh")
}

// Hooks the test suite stubs; production defaults.
var (
	lintFS             policy.FS = policy.RealFS()
	auditRulesActiveFn           = auditRulesActive
	sudoAvailableFn              = sudoAvailable
	sudoTimeoutTagFn             = sudoTimeoutTag
	visudoCheckFn                = visudoCheck
)
