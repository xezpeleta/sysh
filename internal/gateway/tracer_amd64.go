//go:build linux && amd64

// Traced agent scripts (§6.13): a real interpreter — any shebang —
// runs as a child of this gateway while a ptrace tracer intercepts
// every execve in its process tree. The argv is read from the child's
// memory while it is stopped at syscall entry, policy-checked exactly
// like a direct exec, and a refusal fails the syscall itself (-EPERM):
// the interpreter sees "Permission denied", the journal sees
// everything, and the script runs on.
//
// Honest limits (stated in PROJECT.md §6.13, not hidden):
//   - only execve/execveat are inspected. What the interpreter does
//     with builtins and redirections (file writes, arithmetic) is not
//     argv-visible and runs with the unprivileged gateway user's
//     ordinary rights. The operator opts into that by choosing
//     agent_scripts_mode = "traced" for a directory they curate.
//   - the tracer must be the tracee's ancestor, so traced children
//     cannot be delegated to a systemd scope; containment is rlimits,
//     a whole-run timeout, and PTRACE_O_EXITKILL.
//   - the kernel itself suppresses setuid/setgid elevation for traced
//     execs (LSM_UNSAFE_PTRACE: a traced exec never gains privileges
//     the tracer could not already grant), so nothing in the tree can
//     escalate through a setuid binary.
//   - the runtime denylist is not re-applied inside the tree: it
//     exists because a shell runs commands "the policy never sees",
//     and under tracing the policy sees every one of them. The linter
//     still refuses to write rules for those names, so nothing can
//     match them; in permissive mode every execve is journaled.
package gateway

import (
	"github.com/xezpeleta/sysh/internal/policy"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/result"
	"golang.org/x/sys/unix"
)

// Syscall numbers (amd64).
const (
	nrExecve   = 59
	nrExecveat = 322
)

// tracedTraceOpts: EXITKILL is the kill switch — if the gateway dies,
// the kernel SIGKILLs every tracee, so no interpreter outlives its
// session. TRACESYSGOOD marks syscall stops as SIGTRAP|0x80 so they
// cannot be confused with real signals. TRACECLONE/FORK/VFORK make
// every child the interpreter spawns a tracee too.
const tracedTraceOpts = unix.PTRACE_O_EXITKILL | unix.PTRACE_O_TRACESYSGOOD |
	unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACEFORK

const (
	// tracedMaxArgvBytes caps the argv bytes read from a stopped child.
	tracedMaxArgvBytes = 64 << 10

	// tracedMaxArgElem caps one argument read from tracee memory.
	tracedMaxArgElem = 16 << 10
)

// tracedTimeout bounds the whole run (no per-rule timeouts apply
// inside a script). A seam for tests.
var tracedTimeout = 600 * time.Second

// tracedKillSwitch: root disables traced mode instantly — no policy
// round-trip, no reinstall. A seam for tests.
var tracedKillSwitch = "/run/sysh/traced-off"

// pendingExec remembers the decision made at syscall entry so the
// exit stop can act on it (fail the syscall, journal the result).
type pendingExec struct {
	argv    []string
	allowed bool
	ruleIdx int
	detail  string
}

// traceeState is the per-thread tracer bookkeeping.
type traceeState struct {
	// exitPhase: the next syscall stop is the exit half of the call.
	exitPhase bool
	pending   *pendingExec
}

// tracer drives the wait4 loop for one traced script run.
type tracer struct {
	s        *session
	base     audit.Event
	childPid int
	state    map[int]*traceeState
}

// runTracedScript executes a script under ptrace (§6.13). argv names
// the script; any extra words are passed to the interpreter as script
// arguments. Every execve in the tree goes through tracedDecide.
func (s *session) runTracedScript(path string, fromArgv []string, base audit.Event) (int, bool) {
	cfg, emit, ident := s.cfg, s.emit, s.ident

	deny := func(detail string, ev audit.Event) (int, bool) {
		_ = emit(ev)
		result.Write(cfg.Stderr, result.ClassDenied, detail, ident.KeyID, result.ExitDenied)
		return result.ExitDenied, true
	}

	// Kill switch: root can disable traced mode at any moment.
	if _, err := os.Stat(tracedKillSwitch); err == nil {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "traced kill switch"
		return deny("script refused: traced scripts disabled by operator ("+tracedKillSwitch+" exists)", ev)
	}

	// Recursion guard, same as line scripts: a traced script that
	// execs itself must refuse, not loop.
	if s.running == nil {
		s.running = map[string]bool{}
	}
	if s.running[path] {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = "recursive script"
		return deny("script refused: "+path+" is already running (recursive script)", ev)
	}
	s.running[path] = true
	defer delete(s.running, path)

	if err := checkTracedScriptFile(path); err != nil {
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = err.Error()
		return deny("script refused: "+err.Error(), ev)
	}

	runEv := withDec(base, audit.DecisionBuiltin)
	runEv.Detail = "traced script run"
	_ = emit(runEv)

	start := cfg.Now()

	// The gateway forks the interpreter itself (the tracer must be
	// the tracee's parent — scopes delegate to systemd-run and are
	// impossible here). Ptrace:true makes the child call
	// PTRACE_TRACEME before exec, so it lands in trace-stop with the
	// interpreter already loaded. Setpgid gives the tree its own
	// process group for clean kills.
	//
	// Everything below from the fork to the last ptrace request runs
	// on one OS thread: PTRACE_TRACEME records the forking *task* as
	// the tracer, so ptrace calls from any other thread of this
	// process get ESRCH (a busy process migrates goroutines between
	// threads, which is exactly what the stdlib SysProcAttr.Ptrace
	// comment warns about). The goroutine holds runtime.LockOSThread
	// for its whole life; kills from the timeout path are plain
	// kill(2) calls and remain fine from any thread.
	var (
		truncMu   sync.Mutex
		truncated bool
	)
	var mu sync.Mutex
	var live *exec.Cmd // set once the child exists, for killTree
	killTree := func() {
		mu.Lock()
		c := live
		mu.Unlock()
		if c != nil && c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			_ = c.Process.Kill()
		}
	}
	type runResult struct {
		code    int
		startOK bool
		explain func() (string, audit.Event) // deny with a reason when startOK is false
	}
	done := make(chan runResult, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		cmd := exec.Command(path, fromArgv[1:]...)
		cmd.Env = scrubbedEnv(cfg.HomeDir)
		cmd.Dir = workingDir(cfg.HomeDir)
		cmd.Stdin = strings.NewReader("") // a script is the input, like line scripts
		cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}
		stdoutR, stdoutW, err := os.Pipe()
		if err != nil {
			done <- runResult{explain: func() (string, audit.Event) {
				ev := withDec(base, audit.DecisionDeny)
				ev.Detail = err.Error()
				return "cannot start traced script: " + err.Error(), ev
			}}
			return
		}
		stderrR, stderrW, err := os.Pipe()
		if err != nil {
			stdoutR.Close()
			stdoutW.Close()
			done <- runResult{explain: func() (string, audit.Event) {
				ev := withDec(base, audit.DecisionDeny)
				ev.Detail = err.Error()
				return "cannot start traced script: " + err.Error(), ev
			}}
			return
		}
		cmd.Stdout, cmd.Stderr = stdoutW, stderrW
		if err := cmd.Start(); err != nil {
			stdoutR.Close()
			stdoutW.Close()
			stderrR.Close()
			stderrW.Close()
			done <- runResult{explain: func() (string, audit.Event) {
				ev := withDec(base, audit.DecisionDeny)
				ev.Detail = err.Error()
				return "cannot start traced script: " + err.Error(), ev
			}}
			return
		}
		// The child holds its end of the pipes now; it sits in trace-stop
		// until the loop resumes it, so limits land before it runs.
		stdoutW.Close()
		stderrW.Close()
		pgid := cmd.Process.Pid // Setpgid: pid == pgid
		mu.Lock()
		live = cmd
		mu.Unlock()
		setTraceeLimits(pgid)
		stream := func(r *os.File, w io.Writer) {
			limited := &cappedWriter{w: w, remaining: OutputCapBytes, trip: func() {
				truncMu.Lock()
				truncated = true
				truncMu.Unlock()
				killTree()
			}}
			_, _ = io.Copy(limited, r)
			r.Close()
		}
		go stream(stdoutR, cfg.Stdout)
		go stream(stderrR, cfg.Stderr)
		tr := &tracer{s: s, base: base, childPid: pgid, state: map[int]*traceeState{}}
		code := tr.run()
		done <- runResult{code: code, startOK: true}
	}()

	sigs := make(chan os.Signal, 4)
	signalNotify(sigs)
	timeout := time.After(tracedTimeout)

	select {
	case res := <-done:
		if !res.startOK {
			detail, ev := res.explain()
			return deny(detail, ev)
		}
		code := res.code
		post := withDec(base, audit.DecisionBuiltin)
		post.Phase = "post"
		post.Exit = code
		post.DurationMS = cfg.Now().Sub(start).Milliseconds()
		post.Detail = "traced script run"
		post.Truncated = isTruncated(&truncMu, &truncated)
		_ = emit(post)
		rl := result.Line{Class: result.ClassExec, KeyID: ident.KeyID, Exit: &code,
			Truncated: post.Truncated}
		if post.Truncated {
			rl.Class = result.ClassTruncated
			t := result.ExitTimeout
			rl.Exit = &t
			code = result.ExitTimeout
		}
		_ = rl.Write(cfg.Stderr)
		return code, false

	case <-timeout:
		killTree()
		<-done
		ev := withDec(base, audit.DecisionTimeout)
		ev.Phase = "post"
		ev.Exit = result.ExitTimeout
		ev.DurationMS = cfg.Now().Sub(start).Milliseconds()
		ev.Detail = "traced script run"
		_ = emit(ev)
		et := result.ExitTimeout
		_ = result.Line{Class: result.ClassTimeout, KeyID: ident.KeyID, Exit: &et,
			Detail: fmt.Sprintf("killed after %s", tracedTimeout)}.Write(cfg.Stderr)
		return result.ExitTimeout, true

	case sig := <-sigs:
		killTree()
		code := 128 + int(sig.(syscall.Signal))
		<-done
		ev := withDec(base, audit.DecisionSession)
		ev.Phase = "post"
		ev.Detail = sig.String()
		_ = emit(ev)
		_ = result.Line{Class: result.ClassSessionDrop, KeyID: ident.KeyID, Exit: &code,
			Detail: sig.String()}.Write(cfg.Stderr)
		return code, true
	}
}

// run is the tracer's wait4 loop. It returns the script's exit code.
func (t *tracer) run() int {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if err != nil {
			// ECHILD or worse: nothing left to trace.
			return result.ExitDenied
		}
		if ws.Exited() || ws.Signaled() {
			delete(t.state, pid)
			if pid == t.childPid {
				if ws.Exited() {
					return ws.ExitStatus()
				}
				return 128 + int(ws.Signal())
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		switch sig := ws.StopSignal(); {
		case int(sig) == int(unix.SIGTRAP|0x80):
			// Syscall stop (TRACESYSGOOD): the decision point.
			t.syscallStop(pid)
			_ = unix.PtraceSyscall(pid, 0)

		case sig == unix.SIGTRAP && ws.TrapCause() != 0:
			// fork/vfork/clone event: the new child arrives separately
			// with its own SIGSTOP stop, handled below.
			_ = unix.PtraceSyscall(pid, 0)

		case sig == unix.SIGTRAP:
			// Exec stop (the initial one included): a fresh image. The
			// next syscall stop is an entry, and the thread needs the
			// options set (idempotent).
			if st := t.state[pid]; st != nil {
				st.exitPhase = false
				st.pending = nil
			}
			_ = unix.PtraceSetOptions(pid, tracedTraceOpts)
			_ = unix.PtraceSyscall(pid, 0)

		case sig == unix.SIGSTOP:
			// Freshly auto-attached tracee (TRACECLONE/FORK/VFORK
			// child). Swallow the attach stop, set the options, keep
			// it syscall-traced. (A group-stop SIGSTOP is swallowed
			// too — job control inside a traced script is not a
			// supported gesture.)
			if _, ok := t.state[pid]; !ok {
				t.state[pid] = &traceeState{}
			}
			_ = unix.PtraceSetOptions(pid, tracedTraceOpts)
			_ = unix.PtraceSyscall(pid, 0)

		default:
			// Signal-delivery stop: forward the signal to the tracee.
			_ = unix.PtraceSyscall(pid, int(sig))
		}
	}
}

// syscallStop handles one syscall stop for one thread: at entry it
// reads and policy-checks execve argv (failing the syscall when
// refused), at exit it journals the outcome.
func (t *tracer) syscallStop(pid int) {
	st := t.state[pid]
	if st == nil {
		st = &traceeState{}
		t.state[pid] = st
	}
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return
	}

	if !st.exitPhase {
		// Entry half: the argv is frozen in tracee memory — no
		// TOCTOU, the execve has not consumed it yet.
		st.exitPhase = true
		if regs.Orig_rax != nrExecve && regs.Orig_rax != nrExecveat {
			return
		}
		p := &pendingExec{ruleIdx: -1}
		argv, rerr := readExecveArgv(pid, &regs, regs.Orig_rax == nrExecveat)
		if rerr != nil {
			p.argv = []string{"<unreadable-execve>"}
			p.detail = rerr.Error()
		} else {
			p.argv = argv
			p.allowed, p.ruleIdx, p.detail = t.tracedDecide(argv)
		}
		st.pending = p

		ev := t.execEvent(p.argv, "pre")
		if p.ruleIdx >= 0 {
			idx := p.ruleIdx
			ev.Rule = &idx
		}
		if p.allowed {
			_ = t.s.emit(withDec(ev, audit.DecisionAllow))
		} else {
			evd := withDec(ev, audit.DecisionDeny)
			evd.Detail = "traced: " + p.detail
			_ = t.s.emit(evd)
			// Teaching parity: the interpreter only says "Permission
			// denied"; sysh says why, in-band, on the run's stderr.
			// A refused shell or interpreter is almost always the
			// #!/usr/bin/env habit: name the interpreter in the
			// shebang instead (#!/bin/bash) — the kernel loads it
			// before the tracer ever stops, by construction.
			msg := fmt.Sprintf("traced exec refused: %s — %s", strings.Join(p.argv, " "), p.detail)
			if len(p.argv) > 0 {
				if hit := policy.CheckDenylist(p.argv[0], p.argv[0], p.argv); hit != nil && !hit.Warn {
					msg += "; interpreters are named in the script's shebang (#!/bin/bash), not exec'd as commands"
				}
			}
			result.Write(t.s.cfg.Stderr, result.ClassDenied,
				msg, t.s.ident.KeyID, result.ExitDenied)
			// Fail the syscall: an invalid number at entry means the
			// kernel executes nothing; the exit stop turns -ENOSYS
			// into -EPERM so the interpreter reports the true cause.
			regs.Orig_rax = ^uint64(0)
			_ = unix.PtraceSetRegs(pid, &regs)
		}
		return
	}

	// Exit half.
	st.exitPhase = false
	p := st.pending
	st.pending = nil
	if p == nil {
		return
	}
	ev := t.execEvent(p.argv, "post")
	if p.ruleIdx >= 0 {
		idx := p.ruleIdx
		ev.Rule = &idx
	}
	if p.allowed {
		ev = withDec(ev, audit.DecisionAllow)
		if int64(regs.Rax) < 0 {
			ev.Exit = 126 // exec failed (e.g. ENOENT: command not found)
			ev.Detail = fmt.Sprintf("traced: exec failed (errno %d)", -int64(regs.Rax))
		} else {
			ev.Exit = 0
		}
	} else {
		// Turn the skipped syscall's -ENOSYS into -EPERM.
		regs.Rax = ^uint64(uint64(unix.EPERM) - 1) // -EPERM = ~(EPERM-1)
		_ = unix.PtraceSetRegs(pid, &regs)
		ev = withDec(ev, audit.DecisionDeny)
		ev.Exit = result.ExitDenied
		ev.Detail = "traced: exec refused (-EPERM)"
	}
	_ = t.s.emit(ev)
}

// tracedDecide applies the same rule semantics as a direct exec:
// deny rules first (prefix), then allow rules; permissive mode runs
// everything not denied (it is journaled either way). Builtins and
// privileged/approval rules are direct-exec concepts and do not
// apply inside a script tree.
func (t *tracer) tracedDecide(argv []string) (bool, int, string) {
	if len(argv) == 0 || argv[0] == "" {
		return false, -1, "empty argv"
	}
	if len(argv) > maxArgs {
		return false, -1, "too many arguments"
	}
	total := 0
	for _, a := range argv {
		total += len(a)
		if total > tracedMaxArgvBytes {
			return false, -1, "argv too large"
		}
		for i := 0; i < len(a); i++ {
			// Reject control characters and DEL: they never appear in
			// real argv text but do appear when reading half-written
			// memory. Spaces and UTF-8 (>= 0x80) are legitimate argv
			// bytes an interpreter may pass.
			if a[i] < 0x20 || a[i] == 0x7F {
				return false, -1, "argv contains non-printable-ASCII bytes"
			}
		}
	}
	dec := t.s.compiled.Match(argv)
	if !dec.Allowed {
		if dec.Rule != nil && dec.Rule.Deny {
			return false, dec.RuleIdx, fmt.Sprintf("denied by deny rule %d", dec.RuleIdx)
		}
		return false, -1, "no rule allows this argv"
	}
	return true, dec.RuleIdx, ""
}

// execEvent builds a journal event for one traced execve from the
// script-run base event.
func (t *tracer) execEvent(argv []string, phase string) audit.Event {
	ev := t.base
	ev.Argv = argv
	ev.Exit = -1
	ev.Phase = phase
	ev.Rule = nil
	ev.Detail = "traced"
	return ev
}

// readExecveArgv reconstructs the argv of a pending execve (or
// execveat) from the stopped child's memory.
func readExecveArgv(pid int, regs *unix.PtraceRegs, execveat bool) ([]string, error) {
	argvAddr := regs.Rsi
	if execveat {
		// execveat(dirfd, pathname, argv, envp, flags): pathname in
		// rsi, argv in rdx. An fd-based exec (empty pathname) cannot
		// be journaled by argv[0] — refuse it.
		argvAddr = regs.Rdx
		path, err := peekCString(pid, regs.Rsi, tracedMaxArgElem)
		if err == nil && path == "" {
			return nil, fmt.Errorf("fd-based execveat is not supported")
		}
	}
	return peekArgv(pid, argvAddr)
}

// peekArgv reads the NULL-terminated argv pointer array followed by
// each pointed-to string. The child is stopped: this memory is
// stable. Failures deny the exec (fail closed) rather than guess.
func peekArgv(pid int, addr uint64) ([]string, error) {
	if addr == 0 {
		return nil, fmt.Errorf("null argv pointer")
	}
	var argv []string
	word := make([]byte, 8)
	for len(argv) < maxArgs {
		if _, err := unix.PtracePeekData(pid, uintptr(addr), word); err != nil {
			return nil, fmt.Errorf("cannot read argv array: %w", err)
		}
		p := binary.LittleEndian.Uint64(word)
		if p == 0 {
			return argv, nil
		}
		s, err := peekCString(pid, p, tracedMaxArgElem)
		if err != nil {
			return nil, err
		}
		argv = append(argv, s)
		addr += 8
	}
	return nil, fmt.Errorf("too many arguments")
}

// peekCString reads one NUL-terminated string from tracee memory,
// word by word, capped at max bytes.
func peekCString(pid int, addr uint64, max int) (string, error) {
	if addr == 0 {
		return "", fmt.Errorf("null string pointer")
	}
	var buf bytes.Buffer
	word := make([]byte, 8)
	for buf.Len() < max {
		if _, err := unix.PtracePeekData(pid, uintptr(addr), word); err != nil {
			return "", fmt.Errorf("cannot read string at %#x: %w", addr, err)
		}
		if i := bytes.IndexByte(word, 0); i >= 0 {
			buf.Write(word[:i])
			return buf.String(), nil
		}
		buf.Write(word)
		addr += 8
	}
	return "", fmt.Errorf("argument longer than %d bytes", max)
}

// setTraceeLimits is the containment in place of a systemd scope
// (the tracer must be the parent, so scope delegation is impossible):
// CPU seconds (the timeout already bounds the wall clock), process
// count mirroring ScopeTasksMax, address space, and file size.
// RLIMIT_NPROC counts every task of the gateway uid, so concurrent
// traced runs share the budget — that is the intended bound. A seam
// for tests (a shared-uid dev machine can already exceed it).
var setTraceeLimits = func(pid int) {
	cpu := unix.Rlimit{Cur: uint64(tracedTimeout/time.Second) + 60, Max: uint64(tracedTimeout/time.Second) + 60}
	_ = unix.Prlimit(pid, unix.RLIMIT_CPU, &cpu, nil)
	nproc := unix.Rlimit{Cur: ScopeTasksMax, Max: ScopeTasksMax}
	_ = unix.Prlimit(pid, unix.RLIMIT_NPROC, &nproc, nil)
	as := unix.Rlimit{Cur: 1 << 30, Max: 1 << 30}
	_ = unix.Prlimit(pid, unix.RLIMIT_AS, &as, nil)
	fsize := unix.Rlimit{Cur: 64 << 20, Max: 64 << 20}
	_ = unix.Prlimit(pid, unix.RLIMIT_FSIZE, &fsize, nil)
}
