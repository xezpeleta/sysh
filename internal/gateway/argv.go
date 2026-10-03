// Package gateway implements the sysh login-shell semantics (§6):
// argv is the unit of trust — whitespace split, no shell semantics,
// printable-ASCII only.
package gateway

import "errors"

var (
	ErrEmpty        = errors.New("empty command")
	ErrNonPrintable = errors.New("argv contains non-printable-ASCII bytes")
	ErrTooManyArgs  = errors.New("too many arguments")
	ErrTooLong      = errors.New("command string too long")
)

const (
	maxArgs      = 256
	maxCmdString = 65536
)

// SplitCommand splits the sshd-provided command string on spaces and
// tabs with no shell semantics whatsoever, and rejects any byte outside
// printable ASCII (0x21–0x7E) plus the two separators (§6.1). This
// defeats terminal-escape / bidi / homoglyph attacks downstream and
// makes hashing and logging unambiguous.
func SplitCommand(cmd string) ([]string, error) {
	if len(cmd) == 0 {
		return nil, ErrEmpty
	}
	if len(cmd) > maxCmdString {
		return nil, ErrTooLong
	}
	var argv []string
	cur := make([]byte, 0, 32)
	flush := func() {
		if len(cur) > 0 {
			argv = append(argv, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(cmd); i++ {
		b := cmd[i]
		switch {
		case b == 0x20 || b == 0x09: // space, tab: separators
			flush()
		case b >= 0x21 && b <= 0x7E: // printable ASCII
			cur = append(cur, b)
		default:
			return nil, ErrNonPrintable
		}
	}
	flush()
	if len(argv) == 0 {
		return nil, ErrEmpty
	}
	if len(argv) > maxArgs {
		return nil, ErrTooManyArgs
	}
	return argv, nil
}
