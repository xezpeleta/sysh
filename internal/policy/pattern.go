package policy

import (
	"fmt"
	"regexp"
	"regexp/syntax"
)

// Pattern semantics (§6.2):
//
// An argv position is a LITERAL (compared bytewise for equality) unless
// it contains one of the metacharacters \ | ( ) [ ] { } * + ? — then it
// is compiled as an anchored RE2 pattern. '.' '^' '$' do not trigger
// pattern mode (unit names like nginx.service stay literal), but inside
// an explicit pattern they carry their regex meaning; the linter warns
// about unescaped '.'.
//
// The linter derives, from the RE2 syntax tree, the set of characters a
// pattern can start with, and rejects any pattern whose first-character
// set contains '-' (option injection) or that can match the empty string.

// metaChars: presence of any of these makes a position a pattern.
const metaChars = `\|()[]{}*+?`

// isPattern reports whether s contains grammar metacharacters.
func isPattern(s string) bool { return hasMeta(s) }

func hasMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(metaChars); j++ {
			if s[i] == metaChars[j] {
				return true
			}
		}
	}
	return false
}

// Position is one compiled argv position.
type Position struct {
	Raw string
	Re  *regexp.Regexp // nil for literals
}

// CompilePosition compiles one argv position.
func CompilePosition(s string) (Position, error) {
	if !hasMeta(s) {
		return Position{Raw: s}, nil
	}
	re, err := regexp.Compile(`\A(?:` + s + `)\z`)
	if err != nil {
		return Position{}, fmt.Errorf("pattern %q: %w", s, err)
	}
	return Position{Raw: s, Re: re}, nil
}

// Match reports whether arg matches this position.
func (p Position) Match(arg string) bool {
	if p.Re == nil {
		return p.Raw == arg
	}
	return p.Re.MatchString(arg)
}

// IsPattern reports whether this position is regex-backed.
func (p Position) IsPattern() bool { return p.Re != nil }

// PatInfo is the static analysis of a pattern position.
type PatInfo struct {
	First       runeSet  // possible first characters of any match
	CanEmpty    bool     // can the pattern match the empty string?
	HasAnyChar  bool     // contains unescaped '.' (over-broad match warning)
}

// AnalyzePattern parses s as RE2 and computes its first-character set.
// It returns an error for constructs the grammar does not allow:
// case-insensitive patterns, and (only where the first character is
// decided) constructs that could match '-': unescaped '.', any-char,
// or a char class containing '-' in its first position set.
func AnalyzePattern(s string) (PatInfo, error) {
	if !hasMeta(s) {
		// literal: trivially safe, no first-char restriction applies
		return PatInfo{}, nil
	}
	re, err := syntax.Parse(s, syntax.Perl)
	if err != nil {
		return PatInfo{}, fmt.Errorf("pattern %q: %w", s, err)
	}
	set, canEmpty, err := firstSet(re)
	if err != nil {
		return PatInfo{}, fmt.Errorf("pattern %q: %w", s, err)
	}
	return PatInfo{
		First:      set,
		CanEmpty:   canEmpty,
		HasAnyChar: hasAnyChar(re),
	}, nil
}

// firstSet walks the syntax tree computing the set of runes a match can
// start with, and whether the whole pattern can match empty.
func firstSet(re *syntax.Regexp) (runeSet, bool, error) {
	if re.Flags&syntax.FoldCase != 0 {
		return nil, false, fmt.Errorf("case-insensitive patterns (?i) are not supported")
	}
	switch re.Op {
	case syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		// zero-width: contributes nothing, matches empty
		return runeSet{}, true, nil

	case syntax.OpNoMatch:
		return runeSet{}, false, nil // matches nothing; caller flags it

	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return runeSet{}, true, nil
		}
		return runeSet{{re.Rune[0], re.Rune[0]}}, false, nil

	case syntax.OpCharClass:
		if len(re.Rune)%2 != 0 {
			return nil, false, fmt.Errorf("malformed character class")
		}
		var set runeSet
		for i := 0; i+1 < len(re.Rune); i += 2 {
			set = append(set, [2]rune{re.Rune[i], re.Rune[i+1]})
		}
		return set, false, nil

	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return nil, false, fmt.Errorf("can match any character (unescaped '.'?) — could match a leading '-'")

	case syntax.OpCapture:
		return firstSet(re.Sub[0])

	case syntax.OpStar, syntax.OpQuest:
		s, _, err := firstSet(re.Sub[0])
		return s, true, err

	case syntax.OpPlus:
		return firstSet(re.Sub[0])

	case syntax.OpRepeat:
		switch {
		case re.Max == 0:
			return runeSet{}, true, nil
		case re.Min == 0:
			s, _, err := firstSet(re.Sub[0])
			return s, true, err
		default:
			return firstSet(re.Sub[0])
		}

	case syntax.OpConcat:
		var acc runeSet
		allEmpty := true
		for _, sub := range re.Sub {
			s, ce, err := firstSet(sub)
			if err != nil {
				return nil, false, err
			}
			acc = acc.union(s)
			if !ce {
				allEmpty = false
				break
			}
		}
		return acc, allEmpty, nil

	case syntax.OpAlternate:
		var acc runeSet
		anyEmpty := false
		for _, sub := range re.Sub {
			s, ce, err := firstSet(sub)
			if err != nil {
				return nil, false, err
			}
			acc = acc.union(s)
			anyEmpty = anyEmpty || ce
		}
		return acc, anyEmpty, nil
	}
	return nil, false, fmt.Errorf("unsupported regexp op %v", re.Op)
}

// hasAnyChar reports any unescaped '.' anywhere in the tree (lint warning).
func hasAnyChar(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return true
	}
	for _, sub := range re.Sub {
		if hasAnyChar(sub) {
			return true
		}
	}
	return false
}

// runeSet is a list of inclusive rune ranges.
type runeSet [][2]rune

// Contains reports whether r is in the set.
func (s runeSet) Contains(r rune) bool {
	for _, rg := range s {
		if r >= rg[0] && r <= rg[1] {
			return true
		}
	}
	return false
}

// Empty reports whether the set can match nothing at all.
func (s runeSet) Empty() bool { return len(s) == 0 }

// String renders the set for diagnostics and tests: small ASCII ranges
// expand to their characters, wide or non-ASCII ranges summarize.
func (s runeSet) String() string {
	var chars []rune
	for _, rg := range s {
		if rg[1] < rg[0] {
			continue
		}
		if rg[1] > 0x7e || rg[1]-rg[0] > 64 {
			return fmt.Sprintf("<%d-range set>", len(s))
		}
		for r := rg[0]; r <= rg[1]; r++ {
			chars = append(chars, r)
		}
	}
	// sort + dedupe
	for i := 1; i < len(chars); i++ {
		for j := i; j > 0 && chars[j] < chars[j-1]; j-- {
			chars[j], chars[j-1] = chars[j-1], chars[j]
		}
	}
	out := chars[:0]
	for i, r := range chars {
		if i == 0 || r != chars[i-1] {
			out = append(out, r)
		}
	}
	return string(out)
}

func (s runeSet) union(o runeSet) runeSet {
	return append(append(runeSet{}, s...), o...)
}
