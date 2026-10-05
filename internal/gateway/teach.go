// Teaching helpers for the no-rule deny path (§6.12). Live-tested
// with an unbriefed agent: its first mistakes were shell operators
// ("uptime && whoami"), bare binary names ("uptime"), and hunting
// for an upload builtin ("put", "write", "sysh-put"...). Each hint
// below answers one of those, using only facts sy-policy publishes.

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/xezpeleta/sysh/internal/policy"
)

// shellOperatorArgv reports whether any argv element is (or embeds)
// a shell operator — the agent tried "uptime && whoami && id" as a
// single exec. argv is split on whitespace; operators are literal
// words that no rule will ever allow.
func shellOperatorArgv(argv []string) bool {
	for _, a := range argv {
		if a == "&&" || a == "||" || a == ";" || a == "|" || a == "&" {
			return true
		}
		if strings.Contains(a, "&&") || strings.HasSuffix(a, ";") {
			return true
		}
	}
	return false
}

// operatorArgWord returns the first argv element that is a shell
// operator or redirection — the words an unbriefed agent sends when
// it treats the channel as a shell ("apt-get update 2>&1 | tail -5").
// Used on the ALLOW path too: in modes where the command runs, the
// operators become literal arguments and the failure the child
// reports is confusing and undeserved. One quiet stderr note saves
// the round-trips.
func operatorArgWord(argv []string) string {
	redirs := map[string]bool{
		"&&": true, "||": true, ";": true, "|": true, "&": true,
		">": true, ">>": true, "<": true, "2>": true, "1>": true,
		"2>>": true, "1>>": true, "2>&1": true, "1>&2": true, ">&": true,
	}
	for _, a := range argv {
		if redirs[a] {
			return a
		}
		if strings.Contains(a, "&&") || strings.HasSuffix(a, ";") {
			return a
		}
	}
	return ""
}

// absPathHint returns the absolute path a bare argv[0] should be
// sent as, when some rule names that binary by its full path.
// "uptime" denied while "/usr/bin/uptime" is rule 0 is a round-trip
// the channel can save — and the hint leaks nothing sy-policy
// doesn't already print.
func absPathHint(c *policy.Compiled, name string) string {
	if name == "" || strings.ContainsRune(name, '/') {
		return ""
	}
	for i := range c.Rules {
		r := c.Rules[i].Rule
		if r == nil || r.Deny {
			continue
		}
		if r.Path != "" && filepath.Base(r.Path) == name {
			return r.Path
		}
		for _, pos := range r.Argv {
			if pos != "" && filepath.Base(pos) == name && strings.ContainsRune(pos, '/') {
				return pos
			}
		}
	}
	return ""
}

// transferNames: the tools an agent reaches for to upload a script.
// The intended path is an operator-acknowledged rsync rule scoped to
// the agent-scripts directory; scp/sftp are denylisted outright, so
// their escape-hatch detail redirects here too.
var transferNames = map[string]bool{
	"scp": true, "sftp": true, "rsync": true,
}

// isTransferName reports whether a (bare or absolute) program name
// is a transfer tool.
func isTransferName(name string) bool {
	return transferNames[filepath.Base(name)]
}

// transferTeaching reports whether this argv is a transfer attempt
// worth explaining (only when scripts are enabled — otherwise there
// is nothing to upload to).
func transferTeaching(pol *policy.Policy, argv []string) bool {
	if pol == nil || pol.AgentScripts == "" || len(argv) == 0 {
		return false
	}
	return isTransferName(argv[0])
}
