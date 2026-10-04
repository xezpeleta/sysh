// Package policy implements the §6/§7 policy model: TOML policy files,
// the restricted pattern grammar (§6.2), the hardened matcher, the
// fail-closed loader, and the mandatory linter.
package policy

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// Modes.
const (
	ModeEnforcing  = "enforcing"
	ModePermissive = "permissive"
)

// Policy is the parsed TOML document (§7).
type Policy struct {
	Version int    `toml:"version"`
	Host    string `toml:"host"`
	Mode    string `toml:"mode"`
	Rules   []Rule `toml:"rule"`
}

// Rule is one allow or deny rule.
type Rule struct {
	Argv       []string `toml:"argv"`
	Path       string   `toml:"path"` // absolute binary path (allow rules)
	Deny       bool     `toml:"deny"`
	Rest       string   `toml:"rest"`    // opt-in pattern for extra positions
	Timeout    int      `toml:"timeout"` // seconds, 1..3600
	Privileged bool     `toml:"privileged"`
	Approval   bool     `toml:"approval"` // privileged + per-exec operator approval (phase 2)
	Ack        bool     `toml:"ack"`      // acknowledges linter warnings on this rule
}

// Parse decodes and structurally validates policy bytes. Unknown TOML
// fields are refused: a typo ("aprovval", "timeouts") must never read
// as a policy that quietly lacks the property the operator meant to set.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&p)
	if err != nil {
		return nil, fmt.Errorf("policy: TOML parse error: %w", err)
	}
	if unknown := md.Undecoded(); len(unknown) > 0 {
		parts := make([]string, len(unknown))
		for i, k := range unknown {
			parts[i] = k.String()
		}
		return nil, fmt.Errorf("policy: unknown field(s): %s — typos are policy, refused", strings.Join(parts, ", "))
	}
	if p.Version != 2 {
		return nil, fmt.Errorf("policy: version must be 2, got %d", p.Version)
	}
	if p.Mode == "" {
		p.Mode = ModeEnforcing
	}
	if p.Mode != ModeEnforcing && p.Mode != ModePermissive {
		return nil, fmt.Errorf("policy: mode must be %q or %q, got %q", ModeEnforcing, ModePermissive, p.Mode)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if len(r.Argv) == 0 {
			return nil, fmt.Errorf("policy: rule %d: empty argv", i)
		}
		for _, pos := range r.Argv {
			if pos == "" {
				return nil, fmt.Errorf("policy: rule %d: empty argv position", i)
			}
		}
		if r.Timeout < 0 || r.Timeout > 3600 {
			return nil, fmt.Errorf("policy: rule %d: timeout must be 1..3600 seconds", i)
		}
	}
	return &p, nil
}

// ParseFile reads and parses a policy file (used by the linter/installer
// on operator-controlled input; the gateway uses Load, which adds
// fail-closed filesystem checks).
func ParseFile(path string) (*Policy, []byte, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, data, err
	}
	return p, data, nil
}
