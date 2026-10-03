package policy

// Decision is the matcher outcome (§6.2).
type Decision struct {
	Allowed bool
	RuleIdx int // -1 when no rule matched (permissive mode or denial)
	Rule    *Rule
}

// Compile precompiles all rule positions for fast matching.
func Compile(p *Policy) (*Compiled, error) {
	c := &Compiled{Policy: p}
	for i := range p.Rules {
		r := &p.Rules[i]
		cr := CompiledRule{Rule: r}
		for _, pos := range r.Argv {
			cp, err := CompilePosition(pos)
			if err != nil {
				return nil, err
			}
			cr.Positions = append(cr.Positions, cp)
		}
		if r.Rest != "" {
			cp, err := CompilePosition(r.Rest)
			if err != nil {
				return nil, err
			}
			cr.HasRest = true
			cr.Rest = cp
		}
		c.Rules = append(c.Rules, cr)
	}
	return c, nil
}

// Compiled is a policy with precompiled positions.
type Compiled struct {
	Policy *Policy
	Rules  []CompiledRule
}

type CompiledRule struct {
	Rule      *Rule
	Positions []Position
	HasRest   bool
	Rest      Position
}

// Match applies §6.2: deny rules first (prefix semantics), then the
// first allow match (exact length unless rest). In permissive mode
// everything not denied is allowed.
func (c *Compiled) Match(argv []string) Decision {
	// Deny first, prefix semantics: a deny matches if its positions
	// match the argv's leading positions, regardless of extra args.
	for i := range c.Rules {
		cr := &c.Rules[i]
		if !cr.Rule.Deny {
			continue
		}
		if len(argv) >= len(cr.Positions) && positionsMatch(cr.Positions, argv) {
			return Decision{Allowed: false, RuleIdx: i, Rule: cr.Rule}
		}
	}

	if c.Policy.Mode == ModePermissive {
		return Decision{Allowed: true, RuleIdx: -1}
	}

	// Allow: exact length by default; opt-in rest pattern covers extras.
	for i := range c.Rules {
		cr := &c.Rules[i]
		if cr.Rule.Deny {
			continue
		}
		if len(argv) < len(cr.Positions) {
			continue
		}
		if !positionsMatch(cr.Positions, argv) {
			continue
		}
		extra := argv[len(cr.Positions):]
		if len(extra) == 0 {
			return Decision{Allowed: true, RuleIdx: i, Rule: cr.Rule}
		}
		if cr.HasRest {
			ok := true
			for _, a := range extra {
				if !cr.Rest.Match(a) {
					ok = false
					break
				}
			}
			if ok {
				return Decision{Allowed: true, RuleIdx: i, Rule: cr.Rule}
			}
		}
		// extra positions and no (or non-matching) rest: exact-length default denies
	}
	return Decision{Allowed: false, RuleIdx: -1}
}

func positionsMatch(positions []Position, argv []string) bool {
	for i, p := range positions {
		if !p.Match(argv[i]) {
			return false
		}
	}
	return true
}
