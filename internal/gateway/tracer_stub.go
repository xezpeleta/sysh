//go:build !linux || !amd64

// Traced agent scripts (§6.13) need the amd64 syscall-number and
// register conventions. On any other build, traced mode refuses to
// run — fail closed, with the reason.
package gateway

import (
	"fmt"
	"runtime"

	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/result"
)

func (s *session) runTracedScript(path string, fromArgv []string, base audit.Event) (int, bool) {
	ev := withDec(base, audit.DecisionDeny)
	ev.Detail = "traced mode unsupported"
	detail := fmt.Sprintf("script refused: agent_scripts_mode = traced is not supported on this build (%s/%s); ask your operator to use lines mode",
		runtime.GOOS, runtime.GOARCH)
	_ = s.emit(ev)
	result.Write(s.cfg.Stderr, result.ClassDenied, detail, s.ident.KeyID, result.ExitDenied)
	return result.ExitDenied, true
}
