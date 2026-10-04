package gateway

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xezpeleta/sysh/internal/approval"
	"github.com/xezpeleta/sysh/internal/audit"
	"github.com/xezpeleta/sysh/internal/policy"
	"github.com/xezpeleta/sysh/internal/result"
	"golang.org/x/sys/unix"
)

// Fixed production paths (§3). No environment overrides exist: the sy
// UID controls its environment, so the gateway trusts none of it.
const (
	ProdEtcDir     = "/etc/sysh"
	ProdPolicyPath = "/etc/sysh/policy.toml"
	ProdKeysMap    = "/etc/sysh/keys.map"
	ProdDocsDir    = "/etc/sysh/docs"
	ProdTripwire   = "/run/sysh-tripwire/lockdown"
	ProdHome       = "/var/lib/sysh"
)

// Containment defaults (documented; policy rules may set a timeout).
const (
	DefaultTimeoutSec = 60
	MaxTimeoutSec     = 3600
	OutputCapBytes    = 1 << 20 // per stream
	ScopeTasksMax     = 256
	ScopeMemoryMax    = "1G"
)

// Gateway user (production). The shell only executes for this account.
const GatewayUser = "sy"

// Config carries the fixed production wiring; tests inject fakes.
type Config struct {
	PolicyPath  string
	KeysMapPath string
	DocsDir     string
	Tripwire    string
	HomeDir     string
	RequestsDir string // phase-2 approval drop box (default /run/sysh/requests)
	ResultsDir  string // phase-2 results (default /run/sysh/results)
	PolicyOwner int    // uid that must own the policy (0 in production)
	Sink        audit.Sink
	Scopes      bool // enable systemd-run --user scopes (auto-probed)
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Getenv      func(string) string
	Now         func() time.Time
}

// Production configuration.
func ProdConfig() Config {
	return Config{
		PolicyPath:  ProdPolicyPath,
		KeysMapPath: ProdKeysMap,
		DocsDir:     ProdDocsDir,
		Tripwire:    ProdTripwire,
		HomeDir:     ProdHome,
		RequestsDir: approval.RequestsDir,
		ResultsDir:  approval.ResultsDir,
		Sink:        audit.JournalSink{},
		Scopes:      UserBusAvailable(os.Getenv),
		PolicyOwner: 0,
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		Now:         time.Now,
	}
}

// Run executes one gateway invocation (the `-c` command string) and
// returns the process exit code. Every terminal outcome emits one
// result line on stderr and (best effort pre/post) journal events.
func Run(cfg Config, cmd string) int {
	start := cfg.Now()

	// Identity is read first thing (§5), before any child exists.
	ident := ReadIdentity(cfg.Getenv, os.ReadFile, cfg.KeysMapPath)

	emit := func(ev audit.Event) error {
		if cfg.Sink == nil {
			return nil
		}
		if ev.Time.IsZero() {
			ev.Time = cfg.Now()
		}
		if ev.KeyID == "" {
			ev.KeyID = ident.KeyID
			ev.Fingerprint = ident.Fingerprint
		}
		return cfg.Sink.Emit(ev)
	}
	deny := func(class, detail string, exit int, ev audit.Event) int {
		_ = emit(ev)
		result.Write(cfg.Stderr, class, detail, ident.KeyID, exit)
		return exit
	}

	// Lockdown (§6.5): any local user may trip it; root clears it.
	if _, err := os.Lstat(cfg.Tripwire); err == nil {
		return deny(result.ClassLockdown, "lockdown tripwire is present; operator must clear it",
			result.ExitLockdown, audit.Event{Decision: audit.DecisionLockdown, Detail: "tripwire present"})
	} else if !os.IsNotExist(err) {
		return deny(result.ClassInternal, fmt.Sprintf("tripwire check failed: %v", err),
			result.ExitDenied, audit.Event{Decision: audit.DecisionInternal, Detail: err.Error()})
	}

	// Key expiry (§5): keys.map may carry an "expires:" date for the
	// invoking key — TTL enforced by the gateway, on the host, with no
	// certificate authority to protect elsewhere. An expired key is
	// refused like any other deny, with the same journal record.
	if !ident.Expires.IsZero() && !cfg.Now().Before(ident.Expires) {
		detail := "key " + ident.KeyID + " expired on " + ident.Expires.UTC().Format(time.RFC3339) + " (rotate: sysh auth rotate)"
		return deny(result.ClassDenied, detail, result.ExitDenied,
			audit.Event{Decision: audit.DecisionDeny, Detail: "key expired"})
	}

	// argv is the unit of trust (§6.1).
	argv, err := SplitCommand(cmd)
	if err != nil {
		return deny(result.ClassMalformed, err.Error(), result.ExitMalformed,
			audit.Event{Decision: audit.DecisionMalformed, Detail: err.Error()})
	}

	// Load the policy fail-closed (§7): root-owned, single buffer.
	pol, sha, _, err := policy.Load(cfg.PolicyPath, cfg.PolicyOwner)
	if err != nil {
		return deny(result.ClassDenied, "policy unavailable (fail closed): "+err.Error(),
			result.ExitDenied, audit.Event{Decision: audit.DecisionInternal, Detail: err.Error(), Argv: argv})
	}
	compiled, err := policy.Compile(pol)
	if err != nil {
		return deny(result.ClassDenied, "policy uncompilable (fail closed): "+err.Error(),
			result.ExitDenied, audit.Event{Decision: audit.DecisionInternal, Detail: err.Error(), Argv: argv})
	}

	baseEvent := audit.Event{
		Argv:      argv,
		PolicySHA: sha,
		Mode:      pol.Mode,
	}
	if d := compiled.Match(argv); d.RuleIdx >= 0 {
		// attach the matched rule index to every event about this argv
		idx := d.RuleIdx
		baseEvent.Rule = &idx
	}

	// Builtins (§6.3): always allowed, read-only.
	if b := argv[0]; b == "sy-docs" || b == "sy-policy" {
		return runBuiltin(cfg, emit, argv, baseEvent)
	}
	if argv[0] == "sysh-result" {
		return serveResult(cfg, emit, ident, argv, baseEvent)
	}

	dec := compiled.Match(argv)
	if !dec.Allowed {
		ev := withDec(baseEvent, audit.DecisionDeny)
		detail := "no rule allows this argv"
		if dec.Rule != nil && dec.Rule.Deny {
			detail = fmt.Sprintf("denied by deny rule %d", dec.RuleIdx)
			ev.Detail = detail
		}
		return deny(result.ClassDenied, detail, result.ExitDenied, ev)
	}

	// Resolve the binary path.
	path := ""
	if dec.Rule != nil && dec.Rule.Path != "" {
		path = dec.Rule.Path
	} else {
		// permissive mode: argv[0] resolved against the fixed PATH only
		var lpErr error
		path, lpErr = lookPathFixed(argv[0])
		if lpErr != nil {
			ev := withDec(baseEvent, audit.DecisionDeny)
			ev.Detail = lpErr.Error()
			return deny(result.ClassDenied, "cannot resolve command: "+lpErr.Error(),
				result.ExitDenied, ev)
		}
	}

	timeout := DefaultTimeoutSec
	if dec.Rule != nil && dec.Rule.Timeout > 0 {
		timeout = dec.Rule.Timeout
	}

	if dec.Rule != nil && dec.Rule.Privileged && dec.Rule.Approval {
		// Approval rules (§9) never execute in the gateway: the argv
		// is parked in the drop box for a root-side human decision.
		return requestApproval(cfg, emit, ident, argv, dec, baseEvent)
	}

	if dec.Rule != nil && dec.Rule.Privileged {
		// Privileged rules execute as root through the exact-argv
		// sudoers grant generated at policy install (§6.4). Events
		// keep recording the agent's argv; PRIV=1 marks the elevation.
		// The grant only exists if the operator installed this policy,
		// and only for this exact argv — sudo refuses anything else.
		baseEvent.Privileged = true
		var werr error
		argv, path, werr = wrapSudo(argv, path)
		if werr != nil {
			ev := withDec(baseEvent, audit.DecisionInternal)
			ev.Detail = werr.Error()
			return deny(result.ClassInternal, werr.Error(), result.ExitDenied, ev)
		}
	}

	// Pre-exec event, fail closed (P5): if the record cannot be written,
	// the exec does not happen.
	pre := withDec(baseEvent, audit.DecisionAllow)
	pre.Phase = "pre"
	if err := emit(pre); err != nil {
		return deny(result.ClassDenied, "audit sink unavailable (fail closed): "+err.Error(),
			result.ExitDenied, audit.Event{Decision: audit.DecisionInternal, Detail: err.Error(), Argv: argv})
	}

	return execChild(cfg, emit, ident, argv, path, dec, timeout, start, baseEvent)
}

// SudoPath is where the wrapper expects sudo (Debian/Ubuntu layout).
const SudoPath = "/usr/bin/sudo"

// privilegedKillGrace is how long the gateway waits, after a privileged
// child's timeout expires, for sudo's own per-command TIMEOUT to reap
// the root child before the gateway kills the scope itself.
const privilegedKillGrace = 5 * time.Second

// wrapSudo rewrites an allowed privileged argv to run through sudo
// with an exact grant: [sudo, -n, --, binary, args...]. The original
// argv stays in the audit trail; only the exec changes.
func wrapSudo(argv []string, path string) ([]string, string, error) {
	if _, err := os.Stat(SudoPath); err != nil {
		return nil, "", fmt.Errorf("sudo unavailable at %s (privileged rules require it; install sudo or remove the privileged rules)", SudoPath)
	}
	wrapped := make([]string, 0, len(argv)+3)
	wrapped = append(wrapped, SudoPath, "-n", "--")
	wrapped = append(wrapped, path)
	wrapped = append(wrapped, argv[1:]...)
	return wrapped, SudoPath, nil
}

// PolicyUsesPrivileged reports whether the loaded policy contains any
// non-deny privileged rule. The gateway must skip NoNewPrivs in that
// case (sudo needs setuid); fail closed: any load error returns false,
// keeping NNP on.
func PolicyUsesPrivileged(policyPath string, ownerUID int) bool {
	pol, _, _, err := policy.Load(policyPath, ownerUID)
	if err != nil {
		return false
	}
	for i := range pol.Rules {
		r := &pol.Rules[i]
		// Approval rules never elevate in the gateway (the root-side
		// approver executes them, not this process tree), so they do
		// not require NNP off.
		if r.Privileged && !r.Deny && !r.Approval {
			return true
		}
	}
	return false
}

func withDec(ev audit.Event, decision string) audit.Event {
	ev.Decision = decision
	return ev
}

// execChild runs the resolved binary under containment (§6.7) and
// reports the outcome. Raw child stdout/stderr stream to the client
// through the gateway with a byte cap; on cap or timeout the whole
// scope/process group is killed.
func execChild(cfg Config, emit func(audit.Event) error, ident Identity, argv []string, path string,
	dec policy.Decision, timeoutSec int, start time.Time, base audit.Event) int {

	useScope := cfg.Scopes
	unit := ""
	if useScope {
		unit = fmt.Sprintf("sysh-%s-%d", SanitizeUnit(ident.KeyID), start.UnixNano())
	}

	var cmd *exec.Cmd
	if useScope {
		cmd = exec.Command("/usr/bin/systemd-run",
			"--user", "--scope", "--quiet",
			"--unit", unit,
			"-p", fmt.Sprintf("TasksMax=%d", ScopeTasksMax),
			"-p", "MemoryMax="+ScopeMemoryMax,
			"--", path)
		cmd.Args = append(cmd.Args, argv[1:]...)
		// systemd-run needs the user-bus environment to reach the user
		// manager; the child inherits it (any sy process can reach its
		// own user manager regardless — R4-class, tripwired by doctor).
		cmd.Env = append(scrubbedEnv(cfg.HomeDir), busEnv(cfg.Getenv)...)
	} else {
		cmd = exec.Command(path, argv[1:]...)
		cmd.Env = scrubbedEnv(cfg.HomeDir)
	}
	cmd.Dir = workingDir(cfg.HomeDir)
	cmd.Stdin = cfg.Stdin

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return internalErr(cfg, emit, base, err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return internalErr(cfg, emit, base, err)
	}
	cmd.Stdout, cmd.Stderr = stdoutW, stderrW

	if err := cmd.Start(); err != nil {
		stdoutR.Close()
		stderrR.Close()
		stdoutW.Close()
		stderrW.Close()
		ev := withDec(base, audit.DecisionDeny)
		ev.Detail = err.Error()
		return denyResult(cfg, emit, ev, result.ClassDenied, "cannot start command: "+err.Error())
	}
	// The child holds its end of the pipes now.
	stdoutW.Close()
	stderrW.Close()

	// Stream child output through the cap counters.
	var truncMu sync.Mutex
	truncated := false
	stream := func(r *os.File, w io.Writer) {
		limited := &cappedWriter{w: w, remaining: OutputCapBytes, trip: func() {
			truncMu.Lock()
			truncated = true
			truncMu.Unlock()
			killChild(cmd, unit, useScope)
		}}
		_, _ = io.Copy(limited, r)
		r.Close()
	}
	go stream(stdoutR, cfg.Stdout)
	go stream(stderrR, cfg.Stderr)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timeout := time.After(time.Duration(timeoutSec) * time.Second)
	sigs := make(chan os.Signal, 4)
	signalNotify(sigs)

	select {
	case err := <-done:
		code := exitCode(err)
		dur := cfg.Now().Sub(start).Milliseconds()

		post := withDec(base, audit.DecisionAllow)
		post.Phase = "post"
		post.Exit = code
		post.DurationMS = dur
		post.Unit = unit
		post.Scope = useScope
		post.Truncated = isTruncated(&truncMu, &truncated)
		_ = emit(post)

		rl := result.Line{
			Class:     result.ClassExec,
			KeyID:     ident.KeyID,
			Exit:      &code,
			Scope:     useScope,
			Unit:      unit,
			Truncated: post.Truncated,
		}
		if dec.RuleIdx >= 0 {
			idx := dec.RuleIdx
			rl.Rule = &idx
		}
		if post.Truncated {
			rl.Class = result.ClassTruncated
			code = result.ExitTimeout
			rl.Exit = &code
		}
		_ = rl.Write(cfg.Stderr)
		return code

	case <-timeout:
		if base.Privileged {
			// The sudoers grant carries TIMEOUT=<rule timeout>, so
			// sudo's own alarm fires now too — and sudo, running as
			// root, can kill its child, which the user manager (uid
			// sy) cannot. Give sudo a grace period to reap the child
			// before the gateway kills anything: killing sudo first
			// would orphan the root process (reaped only when the
			// user manager stops after the last agent session).
			select {
			case <-done:
			case <-time.After(privilegedKillGrace):
				killChild(cmd, unit, useScope)
				<-done
			}
		} else {
			killChild(cmd, unit, useScope)
			<-done
		}
		ev := withDec(base, audit.DecisionTimeout)
		ev.Phase = "post"
		ev.Exit = result.ExitTimeout
		ev.DurationMS = cfg.Now().Sub(start).Milliseconds()
		ev.Unit = unit
		ev.Scope = useScope
		_ = emit(ev)
		et := result.ExitTimeout
		_ = result.Line{Class: result.ClassTimeout, KeyID: ident.KeyID,
			Exit: &et, Detail: fmt.Sprintf("killed after %ds", timeoutSec),
			Scope: useScope, Unit: unit}.Write(cfg.Stderr)
		return result.ExitTimeout

	case sig := <-sigs:
		killChild(cmd, unit, useScope)
		<-done
		ev := withDec(base, audit.DecisionSession)
		ev.Phase = "post"
		ev.Detail = sig.String()
		ev.Unit = unit
		ev.Scope = useScope
		_ = emit(ev)
		code := 128 + int(sig.(syscall.Signal))
		_ = result.Line{Class: result.ClassSessionDrop, KeyID: ident.KeyID,
			Exit: &code, Detail: "ssh session ended; child killed", Scope: useScope, Unit: unit}.Write(cfg.Stderr)
		return code
	}
}

func isTruncated(mu *sync.Mutex, b *bool) bool {
	mu.Lock()
	defer mu.Unlock()
	return *b
}

// killChild terminates the whole scope (cgroup) and, as a backstop,
// the process group.
func killChild(cmd *exec.Cmd, unit string, useScope bool) {
	if useScope && unit != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "--user", "kill",
			"--kill-whom=all", "--signal=SIGKILL", unit+".scope").Run()
	}
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // process group
		_ = cmd.Process.Kill()
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 125
}

// scrubbedEnv is the fixed execution environment (§6.2): no LD_*,
// no pagers, fixed PATH/HOME/TERM.
func scrubbedEnv(home string) []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"TERM=dumb",
		"LANG=C.UTF-8",
	}
}

func busEnv(getenv func(string) string) []string {
	var env []string
	for _, k := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func workingDir(home string) string {
	if fi, err := os.Stat(home); err == nil && fi.IsDir() {
		return home
	}
	return "/"
}

// lookPathFixed resolves name against the fixed PATH only.
func lookPathFixed(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := dir + "/" + name
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%q not found in the fixed PATH", name)
}

// runBuiltin serves sy-docs / sy-policy (§6.3).
func runBuiltin(cfg Config, emit func(audit.Event) error, argv []string, base audit.Event) int {
	ev := withDec(base, audit.DecisionBuiltin)
	serve := func() (string, int) {
		switch argv[0] {
		case "sy-docs":
			return serveDocs(cfg, argv)
		case "sy-policy":
			data, err := os.ReadFile(cfg.PolicyPath)
			if err != nil {
				return fmt.Sprintf("sy-policy: %v\n", err), 1
			}
			return string(data), 0
		}
		return "unknown builtin", 1
	}
	out, code := serve()
	fmt.Fprint(cfg.Stdout, out)
	_ = emit(ev)
	_ = result.Line{Class: result.ClassBuiltin, KeyID: ev.KeyID, Exit: &code}.Write(cfg.Stderr)
	return code
}

// serveDocs dumps operator-maintained host knowledge (§6.3). Doc names
// are validated strictly; files are opened with O_NOFOLLOW and size caps.
func serveDocs(cfg Config, argv []string) (string, int) {
	const maxDoc = 1 << 20
	if len(argv) > 2 {
		return "usage: sy-docs [name]\n", 1
	}
	if len(argv) == 1 {
		entries, err := os.ReadDir(cfg.DocsDir)
		if err != nil {
			return fmt.Sprintf("sy-docs: %v\n", err), 1
		}
		var names []string
		for _, e := range entries {
			n := e.Name()
			if !e.IsDir() && strings.HasSuffix(n, ".md") && safeDocName(strings.TrimSuffix(n, ".md")) {
				names = append(names, strings.TrimSuffix(n, ".md"))
			}
		}
		sort.Strings(names)
		if len(names) == 0 {
			return "sy-docs: no documents installed; operators add them under " + cfg.DocsDir + "\n", 0
		}
		var b strings.Builder
		b.WriteString("available docs (sy-docs <name>):\n")
		for _, n := range names {
			fmt.Fprintf(&b, "  %s\n", n)
		}
		return b.String(), 0
	}
	name := argv[1]
	if !safeDocName(name) {
		return "sy-docs: invalid document name\n", 1
	}
	path := filepath.Join(cfg.DocsDir, name+".md")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Sprintf("sy-docs: %v\n", err), 1
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return "sy-docs: not a regular file\n", 1
	}
	if st.Size > maxDoc {
		return "sy-docs: document too large\n", 1
	}
	buf := make([]byte, st.Size)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Sprintf("sy-docs: %v\n", err), 1
	}
	return string(buf[:n]), 0
}

func safeDocName(name string) bool {
	if name == "" || len(name) > 64 || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return !strings.Contains(name, "..")
}

// cappedWriter counts bytes and trips the kill on overflow.
type cappedWriter struct {
	w          io.Writer
	remaining  int64
	trip       func()
	trippedMsg bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		if !c.trippedMsg {
			c.trippedMsg = true
			c.trip()
		}
		return 0, nil // drop the rest
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	if c.remaining <= 0 {
		if !c.trippedMsg {
			c.trippedMsg = true
			c.trip()
		}
	}
	return n, err
}

func internalErr(cfg Config, emit func(audit.Event) error, base audit.Event, err error) int {
	ev := withDec(base, audit.DecisionInternal)
	ev.Detail = err.Error()
	_ = emit(ev)
	result.Internal(cfg.Stderr, err.Error())
	return result.ExitDenied
}

func denyResult(cfg Config, emit func(audit.Event) error, ev audit.Event, class, detail string) int {
	_ = emit(ev)
	result.Write(cfg.Stderr, class, detail, ev.KeyID, result.ExitDenied)
	return result.ExitDenied
}

// signalNotify is a seam for tests.
var signalNotify = func(ch chan<- os.Signal) {
	watch := []os.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE}
	sigCh := make(chan os.Signal, len(watch))
	signal.Notify(sigCh, watch...)
	go func() {
		for s := range sigCh {
			ch <- s
		}
	}()
}
