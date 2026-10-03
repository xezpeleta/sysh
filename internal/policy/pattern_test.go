package policy

import "testing"

func TestPatternAnalysis(t *testing.T) {
	tests := []struct {
		pos    string
		first  string // expected first-char set rendering ("" = literal/empty)
		empty  bool
		anyDot bool
		err    bool
	}{
		// literals never enter pattern mode: empty analysis, always safe
		{pos: "nginx.service", first: ""},
		{pos: "/var/log", first: ""},
		// alternations
		{pos: "start|stop|restart", first: "rs"},
		{pos: "(start|stop)|reload", first: "rs"},
		{pos: "re(start|boot)", first: "r"},
		// classes
		{pos: "[a-z0-9@._][a-z0-9@._\\-]*", first: ".0123456789@_abcdefghijklmnopqrstuvwxyz"},
		{pos: "[0-9]+", first: "0123456789"},
		{pos: "(dev|stage)-[a-z]+", first: "ds"},
		{pos: "web[0-9]{2}", first: "w"},
		{pos: "[abc]|xyz", first: "abcx"},
		// quantifiers
		{pos: "a*", first: "a", empty: true},
		{pos: "[a-z]*", first: "abcdefghijklmnopqrstuvwxyz", empty: true},
		{pos: "x|", first: "x", empty: true},
		{pos: "a?b", first: "ab"},
		// unescaped dot warning (matches any char later in the string)
		{pos: "nginx.service.*", first: "n", anyDot: true},
		// leading-dash class: first set contains '-', lint must reject
		{pos: "[-a-z]+", first: "-abcdefghijklmnopqrstuvwxyz"},
		// case-insensitive is rejected
		{pos: "(?i)nginx", err: true},
		// capture groups
		{pos: "(a|b)c", first: "ab"},
	}
	for _, tt := range tests {
		info, err := AnalyzePattern(tt.pos)
		if tt.err {
			if err == nil {
				t.Errorf("AnalyzePattern(%q): expected error, got %+v", tt.pos, info)
			}
			continue
		}
		if err != nil {
			t.Errorf("AnalyzePattern(%q): unexpected error: %v", tt.pos, err)
			continue
		}
		if got := info.First.String(); got != tt.first {
			t.Errorf("AnalyzePattern(%q): first set = %q, want %q", tt.pos, got, tt.first)
		}
		if info.CanEmpty != tt.empty {
			t.Errorf("AnalyzePattern(%q): CanEmpty = %v, want %v", tt.pos, info.CanEmpty, tt.empty)
		}
		if info.HasAnyChar != tt.anyDot {
			t.Errorf("AnalyzePattern(%q): HasAnyChar = %v, want %v", tt.pos, info.HasAnyChar, tt.anyDot)
		}
	}
}

func TestIsPattern(t *testing.T) {
	patterns := []string{"a|b", "[a-z]+", "x*", "(a|b)", "a?b", `a\*b`, "a+b"}
	for _, p := range patterns {
		if !isPattern(p) {
			t.Errorf("isPattern(%q) = false, want true", p)
		}
	}
	// '.' '^' '$' do NOT trigger pattern mode (unit names stay literal)
	literals := []string{"nginx.service", "/usr/bin/true", "hello_world.txt", "a-b-c", "x%y", "^x$", "a$b"}
	for _, l := range literals {
		if isPattern(l) {
			t.Errorf("isPattern(%q) = true, want false (literal)", l)
		}
	}
}

// The linter must reject patterns whose first-character set includes
// '-' (option injection, §6.2).
func TestLinterRejectsLeadingDash(t *testing.T) {
	p := &Policy{Version: 2, Mode: ModeEnforcing, Rules: []Rule{
		{Argv: []string{"/usr/bin/systemctl", "[-a-z]+"}},
	}}
	fs := newMemFS().addFile("/usr/bin/systemctl", 0o755, 0)
	findings := Lint(p, fs)
	found := false
	for _, f := range findings {
		if f.Severity == SevError && containsStr(f.Msg, "leading '-'") {
			found = true
		}
	}
	if !found {
		t.Fatalf("linter did not reject leading-dash pattern: %+v", findings)
	}
}

func TestLinterRejectsEmptyPattern(t *testing.T) {
	p := &Policy{Version: 2, Mode: ModeEnforcing, Rules: []Rule{
		{Argv: []string{"/usr/bin/true", "[a-z]*"}},
	}}
	fs := newMemFS().addFile("/usr/bin/true", 0o755, 0)
	findings := Lint(p, fs)
	found := false
	for _, f := range findings {
		if f.Severity == SevError && containsStr(f.Msg, "empty string") {
			found = true
		}
	}
	if !found {
		t.Fatalf("linter did not reject empty-matching pattern: %+v", findings)
	}
}

func TestLinterRejectsFoldCase(t *testing.T) {
	p := &Policy{Version: 2, Mode: ModeEnforcing, Rules: []Rule{
		{Argv: []string{"/usr/bin/true", "(?i)nginx"}},
	}}
	fs := newMemFS().addFile("/usr/bin/true", 0o755, 0)
	findings := Lint(p, fs)
	found := false
	for _, f := range findings {
		if f.Severity == SevError && containsStr(f.Msg, "case") {
			found = true
		}
	}
	if !found {
		t.Fatalf("linter did not reject (?i): %+v", findings)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
