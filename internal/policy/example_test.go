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

// TestWebserverExampleIsValid keeps the shipped web-server example
// honest: parse + lint clean (all acks present, patterns safe, no
// patterns inside privileged rules).
func TestWebserverExampleIsValid(t *testing.T) {
	data, err := os.ReadFile("../../examples/webserver/policy.toml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("webserver example does not parse: %v", err)
	}

	fs := newMemFS()
	for i := range p.Rules {
		if p.Rules[i].Path != "" {
			fs.addFile(p.Rules[i].Path, 0o755, 0)
		}
	}
	for _, f := range Lint(p, fs) {
		if f.Severity == SevError {
			t.Errorf("webserver example error: %s", f)
		}
		if f.Severity == SevWarning {
			t.Errorf("webserver example warning (install would refuse): %s", f)
		}
	}

	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	allowed := [][]string{
		{"/usr/bin/uptime"},
		{"/usr/bin/systemctl", "status", "apache2"},
		{"/usr/bin/tail", "-n", "100", "/var/log/apache2/error.log"},
		{"/usr/bin/cat", "/etc/apache2/ports.conf"},
		{"/usr/bin/systemctl", "reload", "apache2"},
	}
	for _, argv := range allowed {
		if d := c.Match(argv); !d.Allowed {
			t.Errorf("webserver example denied %v", argv)
		}
	}
	// the apache restart is approval-gated: it must still match (the
	// gateway turns it into a request, exit 30 — never a silent denial
	// and never a standing grant)
	if d := c.Match([]string{"/usr/bin/systemctl", "restart", "apache2"}); !d.Allowed || d.Rule == nil || !d.Rule.Approval || !d.Rule.Privileged {
		t.Errorf("webserver example restart must be privileged+approval-gated, got %+v", d)
	}
	denied := [][]string{
		{"/usr/bin/sudo", "-n", "id"},
		{"/bin/su"},
		{"/usr/bin/tail", "-n", "50", "/var/log/auth.log"},
		{"/usr/bin/tee", "/etc/apache2/apache2.conf"},
		{"/usr/bin/cat", "/etc/shadow"},
	}
	for _, argv := range denied {
		if d := c.Match(argv); d.Allowed {
			t.Errorf("webserver example let %v through", argv)
		}
	}
}
