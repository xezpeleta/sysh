//go:build linux && amd64

// Traced agent scripts (§6.13): a real interpreter under ptrace, every
// execve in its tree policy-checked. These tests need /bin/bash on
// the host; everything else is the standard harness.
package gateway

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xezpeleta/sysh/internal/audit"
	"golang.org/x/sys/unix"
)

const tracedPolicy = `
version = 2
host = "test"
mode = "enforcing"
agent_scripts = "%s"
agent_scripts_mode = "traced"

[[rule]]
argv = ["/bin/echo"]
path = "/bin/echo"
rest = "[a-zA-Z0-9@._:\\- ]*"

[[rule]]
argv = ["/bin/sleep"]
path = "/bin/sleep"
rest = "[0-9]*"
`

// tracedTestConfig mirrors scriptTestConfig with traced mode on.
func tracedTestConfig(t *testing.T, mode string) (Config, *audit.Recorder, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	tracedInit(t)
	base := t.TempDir()
	dir := filepath.Join(base, "agent-scripts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(tracedPolicy, "%s", dir)
	doc = strings.Replace(doc, `mode = "enforcing"`, `mode = "`+mode+`"`, 1)
	cfg, rec, stdout, stderr := testConfig(t, doc)
	return cfg, rec, stdout, stderr, dir
}

func writeTracedScript(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// tracedInit drops the production rlimit set to the CPU cap only: the
// dev machine's uid already exceeds RLIMIT_NPROC=256 once threads are
// counted, and a hit makes bash fork-retry for ~15s instead of
// failing fast. On the sy uid (gateway + tracees only) the full set
// stands.
func tracedInit(t *testing.T) {
	t.Helper()
	old := setTraceeLimits
	setTraceeLimits = func(pid int) {
		cpu := unix.Rlimit{Cur: 660, Max: 660}
		_ = unix.Prlimit(pid, unix.RLIMIT_CPU, &cpu, nil)
	}
	t.Cleanup(func() { setTraceeLimits = old })
}

func needBash(t *testing.T) {
	t.Helper()
	for _, b := range []string{"bash", "sleep"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("no %s on host: %v", b, err)
		}
	}
	for _, p := range []string{"/bin/echo", "/usr/bin/whoami", "/bin/sleep"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s missing", p)
		}
	}
}

func TestTracedScriptAllowDenyContinue(t *testing.T) {
	needBash(t)
	cfg, rec, stdout, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "batch.sh", `#!/bin/bash
/bin/echo first
/usr/bin/whoami
/bin/echo done
`, 0o700)
	// /usr/bin/whoami has no rule: the execve is refused with -EPERM;
	// bash reports "Permission denied" and runs on (no set -e).
	code := Run(cfg, p)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got != "first\ndone\n" {
		t.Fatalf("stdout = %q", got)
	}
	// glibc strerror(EPERM) = "Operation not permitted"; bash prints it
	// for the failed execve.
	if !strings.Contains(stderr.String(), "ot permitted") {
		t.Fatalf("stderr missing bash's refusal: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "traced exec refused: /usr/bin/whoami") {
		t.Fatalf("stderr missing sysh teaching line: %q", stderr.String())
	}
	var allow, deny int
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionBuiltin {
			continue
		}
		if ev.Phase == "pre" && ev.Decision == audit.DecisionAllow {
			allow++
		}
		if ev.Phase == "pre" && ev.Decision == audit.DecisionDeny {
			deny++
		}
	}
	if allow != 2 || deny != 1 {
		t.Fatalf("pre events: allow=%d deny=%d (want 2/1); all: %+v", allow, deny, rec.Events)
	}
}

func TestTracedScriptPassesArguments(t *testing.T) {
	needBash(t)
	cfg, _, stdout, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "args.sh", "#!/bin/bash\n/bin/echo \"script got: $1\"\n", 0o700)
	code := Run(cfg, p+" hello")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got != "script got: hello\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestTracedScriptNestedInterpreterDenied(t *testing.T) {
	needBash(t)
	cfg, _, stdout, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "nested.sh", `#!/bin/bash
/bin/bash -c "/bin/echo nested"
/bin/echo survived
`, 0o700)
	code := Run(cfg, p)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	// The nested bash execve has no rule (the linter would never
	// write one) and is refused; the script survives.
	if !strings.Contains(stderr.String(), "/bin/bash -c") {
		t.Fatalf("nested interpreter not refused: %q", stderr.String())
	}
	if got := stdout.String(); got != "survived\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestTracedScriptExitCodePasses(t *testing.T) {
	needBash(t)
	cfg, _, _, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "fail.sh", "#!/bin/bash\n/bin/echo bye\nexit 42\n", 0o700)
	code := Run(cfg, p)
	if code != 42 {
		t.Fatalf("exit %d (want 42), stderr: %s", code, stderr.String())
	}
}

func TestTracedScriptKillSwitch(t *testing.T) {
	needBash(t)
	cfg, _, _, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "batch.sh", "#!/bin/bash\n/bin/echo no\n", 0o700)
	old := tracedKillSwitch
	tracedKillSwitch = filepath.Join(t.TempDir(), "traced-off")
	if err := os.WriteFile(tracedKillSwitch, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() { tracedKillSwitch = old }()
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d (want 125)", code)
	}
	if !strings.Contains(stderr.String(), "traced scripts disabled by operator") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestTracedScriptNotExecutableRefused(t *testing.T) {
	needBash(t)
	cfg, _, _, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "noexec.sh", "#!/bin/bash\n/bin/echo no\n", 0o600)
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d (want 125), stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "not executable by owner") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestTracedScriptTimeout(t *testing.T) {
	needBash(t)
	cfg, _, _, stderr, dir := tracedTestConfig(t, "enforcing")
	p := writeTracedScript(t, dir, "slow.sh", "#!/bin/bash\n/bin/sleep 30\n", 0o700)
	old := tracedTimeout
	tracedTimeout = 2 * time.Second
	defer func() { tracedTimeout = old }()
	done := make(chan int, 1)
	go func() { done <- Run(cfg, p) }()
	select {
	case code := <-done:
		if code != 124 {
			t.Fatalf("exit %d (want 124), stderr: %s", code, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not finish: tracer loop stuck")
	}
}

func TestTracedScriptPermissiveRunsUnmatched(t *testing.T) {
	needBash(t)
	cfg, _, stdout, stderr, dir := tracedTestConfig(t, "permissive")
	p := writeTracedScript(t, dir, "free.sh", "#!/bin/bash\n/usr/bin/whoami\n", 0o700)
	code := Run(cfg, p)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got == "" {
		t.Fatalf("whoami produced no output in permissive mode")
	}
}

// The help builtin must explain traced mode when it is in force —
// pipes-inside semantics and the bare-argv[0] rule consequence —
// instead of the line-mode "no shell features" text (§6.12, §6.13).
func TestHelpExplainsTracedMode(t *testing.T) {
	tracedInit(t)
	base := t.TempDir()
	dir := filepath.Join(base, "agent-scripts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(tracedPolicy, "%s", dir)
	cfg, _, stdout, _ := testConfig(t, doc)
	if code := Run(cfg, "help"); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	out := stdout.String()
	for _, want := range []string{
		"traced mode: any shebang (bash, python, ...)",
		"each side of a pipe is still a checked exec",
		"for the bare names you use there",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("traced help missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "one command per line, first line #!/usr/bin/sysh") {
		t.Fatalf("traced help must not teach line-mode syntax:\n%s", out)
	}
}

// The console banner must state traced-mode script semantics instead
// of the line-mode "No shell features inside" (§6.11, §6.13).
func TestConsoleBannerTracedMode(t *testing.T) {
	cfg, _, stdout, _, _ := tracedTestConfig(t, "enforcing")
	cfg.Stdin = strings.NewReader("exit\n")
	if code := RunConsole(cfg); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "pipes inside are the") {
		t.Fatalf("traced banner missing pipe note:\n%s", out)
	}
	if strings.Contains(out, "No shell features inside") {
		t.Fatalf("traced banner teaches line mode:\n%s", out)
	}
}
