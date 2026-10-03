package policy

import (
	"os"
	"testing"
)

// TestExamplePolicyIsValid keeps the shipped example policy honest:
// it must parse and lint without errors (unacknowledged warnings would
// also refuse install, so the example must ack everything it warns
// about).
func TestExamplePolicyIsValid(t *testing.T) {
	data, err := os.ReadFile("../../testdata/policy.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("example policy does not parse: %v", err)
	}
	if p.Version != 2 {
		t.Fatalf("example policy version = %d", p.Version)
	}

	// seed a fake FS with every referenced binary
	fs := newMemFS()
	for i := range p.Rules {
		if p.Rules[i].Path != "" {
			fs.addFile(p.Rules[i].Path, 0o755, 0)
		}
	}

	errs, warns := 0, 0
	for _, f := range Lint(p, fs) {
		if f.Severity == SevError {
			errs++
			t.Errorf("example policy error: %s", f)
		}
		if f.Severity == SevWarning {
			warns++
			t.Errorf("example policy warning (install would refuse): %s", f)
		}
	}
	if errs > 0 || warns > 0 {
		t.Fatalf("example policy has %d error(s), %d warning(s)", errs, warns)
	}
}

// The deny rules in the example must actually deny what they claim.
func TestExamplePolicyDenyRules(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/policy.example.toml")
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	denied := [][]string{
		{"find"},
		{"find", "/", "-name", "x"},
		{"/usr/bin/systemctl", "--user", "list-units"},
		{"/usr/bin/systemctl", "--user"},
	}
	for _, argv := range denied {
		if d := c.Match(argv); d.Allowed {
			t.Errorf("example deny rules let %v through", argv)
		}
	}
	allowed := [][]string{
		{"/usr/bin/systemctl", "status", "nginx"},
		{"/usr/bin/systemctl", "is-active", "cron.service"},
		{"/usr/bin/journalctl", "-u", "nginx.service"},
		{"/usr/bin/df", "-h"},
		{"/usr/bin/curl", "-fsSL", "https://example.com/pkg.deb"},
	}
	for _, argv := range allowed {
		if d := c.Match(argv); !d.Allowed {
			t.Errorf("example allow rules denied %v", argv)
		}
	}
	// and the option-injection class stays out
	if d := c.Match([]string{"/usr/bin/journalctl", "-u", "--output=evil"}); d.Allowed {
		t.Error("leading-dash extra arg must not match the rest pattern")
	}
}
