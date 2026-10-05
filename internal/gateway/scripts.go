// Agent scripts (§6.10): the agent's batch workflow, kept inside the
// argv policy. A script is one command per line, first line
// #!/usr/bin/sysh; the gateway reads it whole, checks the shebang and
// the file's ownership, and runs every line through the same decision
// pipeline as a direct exec — same rules, same denylist, same journal.
// No shell semantics exist inside: no variables, no pipes, no
// expansion. The file is data, never exec'd, so a foreign shebang
// (bash, python) can never ride the mechanism.
package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/result"
)

const (
	// ScriptShebang is the only interpreter line an agent script may
	// carry. It names this gateway itself.
	ScriptShebang = "#!/usr/bin/sysh"

	// MaxScriptBytes bounds a script file read into memory.
	MaxScriptBytes = 64 << 10

	// MaxScriptLines bounds how many commands one script may run.
	MaxScriptLines = 1000
)

// agentScriptPath reports whether name resolves to a regular file
// inside dir (after symlinks): either an absolute-ish path under the
// directory, or a bare name looked up in it. Path traversal out of
// the directory is refused by construction.
func agentScriptPath(dir, name string) (string, bool) {
	var cand string
	if filepath.IsAbs(name) {
		cand = name
	} else {
		// bare names and relative subpaths resolve inside the dir;
		// the gateway's cwd is the sy home, so a relative argv[0] must
		// never resolve against it
		cand = filepath.Join(dir, name)
	}
	real, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(dir, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", false
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return real, true
}

// checkScriptFile verifies the file itself: regular, not writable by
// group/world, and owned by the running gateway user or root — the
// agent may own its scripts, but nobody else may plant one.
func checkScriptFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/world-writable (mode %04o — re-upload with mode 0600; rsync -a preserves source permissions)", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot stat owner", path)
	}
	euid := os.Geteuid()
	if int(st.Uid) != euid && int(st.Uid) != 0 {
		return fmt.Errorf("%s: not owned by the gateway user or root", path)
	}
	return nil
}

// runScriptFile executes a script file line by line. fromPolicy is
// the argv that named the script (for events); agentDir is true when
// the script came from the policy's agent-script directory (operator
// scripts reach here via a rule and the kernel's shebang handling —
// but the checks are the same either way).
func (s *session) runScriptFile(path string, fromArgv []string, base audit.Event) (int, bool) {
	deny := func(detail string, ev audit.Event) (int, bool) {
		_ = s.emit(ev)
		result.Write(s.cfg.Stderr, result.ClassDenied, detail, s.ident.KeyID, result.ExitDenied)
		return result.ExitDenied, true
	}

	// Recursion guard: a script whose line names itself (directly or
	// through a chain) must refuse, not loop until the stack dies.
	if s.running == nil {
		s.running = map[string]bool{}
	}
	if s.running[path] {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "recursive script"
		return deny("script refused: "+path+" is already running (recursive script)", ev)
	}

	if err := checkScriptFile(path); err != nil {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = err.Error()
		return deny("script refused: "+err.Error(), ev)
	}

	// Read the whole file once: the lines that run are the lines that
	// were checked — no mid-run rewrite can change what executes.
	data, err := os.ReadFile(path)
	if err != nil {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = err.Error()
		return deny("script refused: cannot read "+path, ev)
	}
	if len(data) > MaxScriptBytes {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "script too large"
		return deny(fmt.Sprintf("script refused: larger than %d bytes", MaxScriptBytes), ev)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > MaxScriptLines+1 {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "too many lines"
		return deny(fmt.Sprintf("script refused: more than %d lines", MaxScriptLines), ev)
	}

	// The shebang gate: the only interpreter an agent script may name
	// is this gateway. A bash or python shebang here would be a free
	// shell with no policy inside — refused with the same teaching
	// the runtime denylist uses.
	first := strings.TrimSpace(lines[0])
	if first != ScriptShebang {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "foreign shebang"
		detail := fmt.Sprintf("script refused: first line must be %s (one command per line, every line policy-checked like a direct exec); bash/python scripts cannot run here — they execute commands this policy never sees", ScriptShebang)
		if first != "" && !strings.HasPrefix(first, "#!") {
			detail = "script refused: missing shebang — first line must be " + ScriptShebang
		}
		return deny(detail, ev)
	}

	// Script event: one allow/builtin pair wrapping the run, so the
	// journal shows the batch itself, then one pre/post pair per line.
	// mark in-progress for the whole run (set before, clear after)
	s.running[path] = true
	defer delete(s.running, path)

	runEv := withDec(base, audit.DecisionBuiltin)
	runEv.Detail = "script run"
	_ = s.emit(runEv)

	// Commands never eat the session's stdin: each line's child gets
	// EOF, like a direct exec with no input.
	// (cfg.Stdin stays whatever the caller set; script sessions set it
	// to an empty reader in RunScriptFile.)

	last := 0
	ran := 0
	for i, raw := range lines[1:] {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ran == MaxScriptLines {
			ev := withDec(base, audit.DecisionDeny)
			ev.Detail = "too many commands"
			return deny(fmt.Sprintf("script aborted: more than %d commands", MaxScriptLines), ev)
		}
		code, denied := s.commandChecked(line)
		ran++
		last = code
		if denied {
			ev := withDec(base, audit.DecisionDeny)
			ev.Detail = fmt.Sprintf("script aborted at line %d", i+2)
			_ = s.emit(ev)
			result.Write(s.cfg.Stderr, result.ClassDenied,
				fmt.Sprintf("script aborted at line %d — see the denial above", i+2),
				s.ident.KeyID, result.ExitDenied)
			return result.ExitDenied, true
		}
	}
	_ = last
	return last, false
}

// RunScriptFile is the interpreter entry point: the kernel invoked
// /usr/bin/sysh on a script whose shebang says so (an operator script
// allowed by an exact rule), or the main dispatch found a script arg.
// Every line runs through the session pipeline.
func RunScriptFile(cfg Config, path string) int {
	s, code, ok := startSession(cfg)
	if !ok {
		return code
	}
	// Script children get EOF stdin; the script itself is the input.
	s.cfg.Stdin = strings.NewReader("")
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	argv := []string{real}
	base := audit.Event{Argv: argv}
	if pol, _, sha, perr := s.loadPolicy(); perr == nil {
		base.PolicySHA = sha
		base.Mode = pol.Mode
		if pol.AgentScripts != "" {
			if p, ok := agentScriptPath(pol.AgentScripts, real); ok {
				argv = []string{p}
				base.Argv = argv
			}
		}
	}
	code, _ = s.runScriptFile(real, argv, base)
	return code
}

// listAgentScripts returns the names of scripts available under dir
// (relative paths, subdirectories included, names only — contents
// are never exposed; an agent runs a script or doesn't). Capped so
// a stuffed directory cannot bloat every help call.
func listAgentScripts(dir string) []string {
	var names []string
	seen := 0
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			// skip the sy-owned drop dir? No — it is the agent's own
			// upload space; its scripts are first-class.
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			return nil
		}
		seen++
		if seen <= 50 {
			names = append(names, rel)
		}
		return nil
	})
	sort.Strings(names)
	return names
}
