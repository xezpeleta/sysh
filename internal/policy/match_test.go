package policy

import "testing"

func pol(mode string, rules ...Rule) *Policy {
	return &Policy{Version: 2, Mode: mode, Rules: rules}
}

func TestMatchExactLength(t *testing.T) {
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/systemctl", "status", "nginx"}})
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "status", "nginx"}); !d.Allowed {
		t.Error("exact argv should match")
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "status", "nginx", "extra"}); d.Allowed {
		t.Error("extra argv must be denied (exact length is the default)")
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "status"}); d.Allowed {
		t.Error("shorter argv must be denied")
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "restart", "nginx"}); d.Allowed {
		t.Error("non-matching literal must be denied")
	}
}

func TestMatchDenyPrefix(t *testing.T) {
	p := pol(ModeEnforcing,
		Rule{Argv: []string{"find"}, Deny: true},
		Rule{Argv: []string{"/usr/bin/find"}, Path: "/usr/bin/find"},
	)
	c, _ := Compile(p)
	// deny matches by argv[0] prefix regardless of path position rules
	if d := c.Match([]string{"find"}); d.Allowed {
		t.Error("deny rule must block bare find")
	}
	if d := c.Match([]string{"find", "/", "-delete"}); d.Allowed {
		t.Error("deny rules have prefix semantics: extra args still denied")
	}
}

func TestMatchDenyBeforeAllow(t *testing.T) {
	// even when an allow rule would match, deny wins
	p := pol(ModeEnforcing,
		Rule{Argv: []string{"/usr/bin/systemctl", "restart", "[a-z-]+"}, Path: "/usr/bin/systemctl"},
		Rule{Argv: []string{"/usr/bin/systemctl", "restart", "nginx"}, Deny: true},
	)
	c, _ := Compile(p)
	if d := c.Match([]string{"/usr/bin/systemctl", "restart", "nginx"}); d.Allowed {
		t.Error("deny must take precedence over allow")
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "restart", "cron"}); !d.Allowed {
		t.Error("non-denied restart should be allowed by pattern rule")
	}
}

func TestMatchRest(t *testing.T) {
	p := pol(ModeEnforcing, Rule{
		Argv: []string{"/usr/bin/journalctl", "-u"},
		Rest: "[a-z0-9@._][a-z0-9@._\\-]*",
		Path: "/usr/bin/journalctl",
	})
	c, _ := Compile(p)
	if d := c.Match([]string{"/usr/bin/journalctl", "-u", "nginx.service"}); !d.Allowed {
		t.Error("rest pattern should allow extra args")
	}
	if d := c.Match([]string{"/usr/bin/journalctl", "-u", "nginx.service", "--evil"}); d.Allowed {
		t.Error("rest pattern must reject non-matching extra args")
	}
	if d := c.Match([]string{"/usr/bin/journalctl", "-u", "-x"}); d.Allowed {
		t.Error("rest pattern must reject leading-dash args")
	}
}

func TestMatchPermissive(t *testing.T) {
	p := pol(ModePermissive,
		Rule{Argv: []string{"curl"}, Deny: true},
	)
	c, _ := Compile(p)
	if d := c.Match([]string{"curl", "http://x"}); d.Allowed {
		t.Error("deny rules still apply in permissive mode")
	}
	if d := c.Match([]string{"any", "argv", "here"}); !d.Allowed {
		t.Error("permissive mode allows non-denied argv")
	}
	if d := c.Match([]string{"curl"}); d.Allowed {
		t.Error("bare deny still applies")
	}
}

func TestMatchLiteralVsPattern(t *testing.T) {
	p := pol(ModeEnforcing, Rule{Argv: []string{"/usr/bin/systemctl", "status", "[a-z-]+.service"}})
	c, _ := Compile(p)
	// "nginx.service" as a position would be a literal; here it is a
	// pattern because it contains '[' — but the '.' matches any char
	if d := c.Match([]string{"/usr/bin/systemctl", "status", "nginx.service"}); !d.Allowed {
		t.Error("pattern should match nginx.service")
	}
	if d := c.Match([]string{"/usr/bin/systemctl", "status", "nginxXservice"}); !d.Allowed {
		t.Error("unescaped '.' matches any char (linter warns about this)")
	}
}
