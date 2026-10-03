package control

import (
	"fmt"
	"io"
	"os"
	"os/exec"
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
	if err := atomicWrite(policyPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sysh policy install: %v\n", err)
		return 1
	}
	fmt.Printf("policy installed from %s (mode=%s, %d rules)\n", source, p.Mode, len(p.Rules))
	return 0
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
	lintFS              policy.FS = policy.RealFS()
	auditRulesActiveFn            = auditRulesActive
)
