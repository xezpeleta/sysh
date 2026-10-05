// The interactive console (§6.11): `ssh sy@host` with no command
// lands here when a TTY is attached. One command per line, each
// through the same decision pipeline as a `-c` exec; the banner at
// connect is the MOTD sysh fully controls. It is an argv REPL, not a
// shell: no variables, no pipes — `cd` is navigation state, not an
// action, and it is the only line the console interprets itself.
package gateway

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/policy"
	"github.com/xezpeleta/sysh/internal/result"
)

// RunConsole runs the interactive session. It never returns a denial
// for the session itself — lines are denied individually, exactly
// like direct execs; the console exits when stdin ends.
func RunConsole(cfg Config) int {
	s, code, ok := startSession(cfg)
	if !ok {
		return code
	}

	// Console commands never eat the session's stdin: the line reader
	// owns it; each command's child gets EOF.
	lineIn := bufio.NewReader(cfg.Stdin)
	s.cfg.Stdin = strings.NewReader("")

	pol, _, _, _ := s.loadPolicy()

	fmt.Fprint(cfg.Stdout, consoleBanner(s, pol))

	cwd, err := os.Getwd()
	if err != nil {
		cwd = workingDir(cfg.HomeDir)
	}

	for {
		fmt.Fprintf(cfg.Stdout, "sy:%s> ", shortDir(cwd, cfg.HomeDir))
		line, rerr := lineIn.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" && rerr != nil {
			break // EOF — the agent closed the channel
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "exit" || trimmed == "quit" {
			break
		}

		// cd: the console's only own verb. Navigation, not action —
		// the kernel enforces who may chdir where; policy paths are
		// absolute and unaffected. Journaled as a builtin.
		if argv, err := SplitCommand(trimmed); err == nil && argv[0] == "cd" && len(argv) <= 2 {
			target := cfg.HomeDir
			if len(argv) == 2 {
				target = argv[1]
			}
			abs, err := filepath.Abs(target)
			if err != nil {
				abs = target
			}
			if err := os.Chdir(abs); err != nil {
				fmt.Fprintf(cfg.Stdout, "cd: %v\n", err)
			} else {
				cwd = abs
				_ = s.emit(withDec(audit.Event{Argv: argv, Mode: modeOf(s)}, audit.DecisionBuiltin))
			}
			s.cfg.Dir = cwd
			continue
		}

		s.commandChecked(trimmed)
	}
	fmt.Fprintln(cfg.Stdout, "bye")
	return 0
}

func modeOf(s *session) string {
	if pol, _, _, _ := s.loadPolicy(); pol != nil {
		return pol.Mode
	}
	return ""
}

// shortDir renders the cwd for the prompt, ~-relative inside home.
func shortDir(dir, home string) string {
	if home != "" && strings.HasPrefix(dir, home) {
		rest := strings.TrimPrefix(dir, home)
		if rest == "" {
			return "~"
		}
		return "~" + rest
	}
	return dir
}

// consoleBanner is the MOTD: the contract, stated once per session,
// in the channel the agent actually sees (sshd prints no MOTD for
// non-interactive sessions — and most agents never open this one).
func consoleBanner(s *session, pol *policy.Policy) string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("sysh — agent channel. argv is the unit of trust.\n")
	b.WriteString("-----------------------------------------------\n")
	mode := policy.ModeEnforcing
	if pol != nil {
		mode = pol.Mode
	}
	fmt.Fprintf(&b, "mode: %s · key: %s\n", mode, s.ident.KeyID)
	b.WriteString("one command per line; each is checked against this\n")
	b.WriteString("host's policy and journaled (pre/post events).\n")
	b.WriteString("  help        how to work here (scripts, limits)\n")
	b.WriteString("  sy-policy   the policy in force\n")
	b.WriteString("  exit        close the session\n")
	if pol != nil && pol.AgentScripts != "" {
		fmt.Fprintf(&b, "scripts: one command per line, first line %s —\n", ScriptShebang)
		fmt.Fprintf(&b, "  upload to %s (needs an operator-acknowledged\n", pol.AgentScripts)
		b.WriteString("  rsync rule — ask); every line is checked like a\n")
		b.WriteString("  direct exec. No shell features inside.\n")
	} else {
		b.WriteString("scripts: not enabled on this host (agent_scripts unset)\n")
	}
	b.WriteString("shells and interpreters (bash, sh, python...) are not\n")
	b.WriteString("executable: they run commands the policy never sees.\n")
	b.WriteString("\n")
	return b.String()
}

// runHelp serves the `help` pseudo-command (§6.3): read-only, always
// allowed with a valid policy (it reports the policy's own facts).
// This is the teaching surface agents actually read — the denial
// details point here.
func (s *session) runHelp(base audit.Event) (int, bool) {
	pol, _, _, _ := s.loadPolicy()
	var b strings.Builder
	b.WriteString("sysh — how to work on this host\n")
	b.WriteString("\n")
	b.WriteString("argv is the unit of trust. Send one command per SSH exec;\n")
	b.WriteString("it is matched exactly against this host's policy and\n")
	b.WriteString("journaled before and after it runs. No shell semantics:\n")
	b.WriteString("no pipes, no variables, no quoting games.\n")
	b.WriteString("\n")
	mode := policy.ModeEnforcing
	if pol != nil {
		mode = pol.Mode
	}
	fmt.Fprintf(&b, "mode: %s\n", mode)
	if pol != nil && pol.AgentScripts != "" {
		fmt.Fprintf(&b, "scripts: %s\n", pol.AgentScripts)
		fmt.Fprintf(&b, "  one command per line, first line %s;\n", ScriptShebang)
		b.WriteString("  run it like any command; every line is policy-checked\n")
		b.WriteString("  and journaled like a direct exec\n")
		if names := listAgentScripts(pol.AgentScripts); len(names) > 0 {
			fmt.Fprintf(&b, "  available: %s\n", strings.Join(names, ", "))
		}
		b.WriteString("  to place one: transfer needs a policy rule your operator\n")
		b.WriteString("  acknowledges (rsync scoped to this directory) — ask them\n")
	} else {
		b.WriteString("scripts: not enabled (agent_scripts unset) — batch work is\n")
		b.WriteString("  one command per SSH exec\n")
	}
	b.WriteString("\n")
	b.WriteString("shells and interpreters (bash, sh, python...) are not\n")
	b.WriteString("executable here: they would run commands this policy never\n")
	b.WriteString("sees. Compute where you live; act here per argv.\n")
	b.WriteString("\n")
	b.WriteString("always available: help, sy-policy, sy-docs, sysh-result\n")

	ev := withDec(base, audit.DecisionBuiltin)
	ev.Detail = "help"
	_ = s.emit(ev)
	fmt.Fprint(s.cfg.Stdout, b.String())
	result.Write(s.cfg.Stderr, "exec", "", s.ident.KeyID, 0)
	// The result line for a successful exec carries the exit code;
	// use the exec-shaped line so tooling treats help like any run.
	return 0, false
}
