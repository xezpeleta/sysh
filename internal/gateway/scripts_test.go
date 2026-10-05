package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xezpeleta/sysh/internal/audit"
)

const scriptPolicy = `
version = 2
host = "test"
mode = "enforcing"
agent_scripts = "%s"

[[rule]]
argv = ["/bin/echo"]
path = "/bin/echo"
rest = "[a-zA-Z0-9@._\\-]*"

[[rule]]
argv = ["/bin/pwd"]
path = "/bin/pwd"
timeout = 10
`

func scriptTestConfig(t *testing.T) (Config, *audit.Recorder, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "agent-scripts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, rec, stdout, stderr := testConfig(t, strings.ReplaceAll(scriptPolicy, "%s", dir))
	// The agent-script dir lives under the same test root so the
	// fail-closed policy loader's ancestor checks hold.
	return cfg, rec, stdout, stderr, dir
}

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunAgentScript(t *testing.T) {
	cfg, rec, stdout, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "deploy.sysh", "#!/usr/bin/sysh\n# comment\n\n/bin/echo one\n/bin/echo two\n")

	code := Run(cfg, p)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "one\ntwo\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	// one pre/post pair per line, plus the script-run builtin event
	var pre, post int
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionBuiltin {
			continue
		}
		switch ev.Phase {
		case "pre":
			pre++
		case "post":
			post++
		}
	}
	if pre != 2 || post != 2 {
		t.Fatalf("events: pre=%d post=%d (want 2/2); all: %+v", pre, post, rec.Events)
	}
}

func TestRunAgentScriptBareName(t *testing.T) {
	cfg, _, stdout, stderr, dir := scriptTestConfig(t)
	writeScript(t, dir, "batch.sysh", "#!/usr/bin/sysh\n/bin/echo bare\n")
	code := Run(cfg, "batch.sysh")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "bare\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunAgentScriptBashShebangRefused(t *testing.T) {
	cfg, _, stdout, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "evil.sh", "#!/bin/bash\n/bin/echo nope\n")
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	line := lastJSONLine(stderr.String())
	if !strings.Contains(line, "first line must be #!/usr/bin/sysh") {
		t.Fatalf("result = %s", line)
	}
	if stdout.String() != "" {
		t.Fatalf("nothing may run: stdout = %q", stdout.String())
	}
}

func TestRunAgentScriptWorldWritableRefused(t *testing.T) {
	cfg, _, _, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "loose.sysh", "#!/usr/bin/sysh\n/bin/echo x\n")
	os.Chmod(p, 0o666)
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	if !strings.Contains(stderr.String(), "group/world-writable") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestRunAgentScriptDenyLineAborts(t *testing.T) {
	cfg, _, stdout, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "mixed.sysh",
		"#!/usr/bin/sysh\n/bin/echo ok\n/usr/bin/rm -rf /\n/bin/echo never\n")
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q (line before the denial runs, after must not)", stdout.String())
	}
	out := stderr.String()
	if !strings.Contains(out, "no rule allows this argv") || !strings.Contains(out, "script aborted at line 3") {
		t.Fatalf("stderr = %s", out)
	}
}

func TestRunScriptFileInterpreter(t *testing.T) {
	cfg, _, stdout, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "interp.sysh", "#!/usr/bin/sysh\n/bin/echo via-interpreter\n")
	code := RunScriptFile(cfg, p)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "via-interpreter\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunAgentScriptTraversalRefused(t *testing.T) {
	cfg, _, _, stderr, dir := scriptTestConfig(t)
	// a script outside the agent dir, named through traversal
	outside := writeScript(t, filepath.Dir(dir), "outside.sysh", "#!/usr/bin/sysh\n/bin/echo x\n")
	code := Run(cfg, filepath.Join(dir, "..", "outside.sysh"))
	if code != 125 {
		t.Fatalf("exit %d, want 125 (traversal out of the dir must not run as a script)", code)
	}
	if !strings.Contains(stderr.String(), "no rule allows this argv") {
		t.Fatalf("stderr = %s (must fall through to the ordinary deny)", stderr.String())
	}
	_ = outside
}

func TestRunHelp(t *testing.T) {
	cfg, rec, stdout, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "help")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"argv is the unit of trust", "mode: enforcing", "scripts: not enabled"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help output missing %q:\n%s", want, out)
		}
	}
	found := false
	for _, ev := range rec.Events {
		if ev.Decision == audit.DecisionBuiltin && ev.Detail == "help" {
			found = true
		}
	}
	if !found {
		t.Fatalf("help must journal a builtin event: %+v", rec.Events)
	}
}

func TestRunDidacticDenyBash(t *testing.T) {
	cfg, _, _, stderr := testConfig(t, execPolicy)
	code := Run(cfg, "/bin/bash -c id")
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	line := lastJSONLine(stderr.String())
	for _, want := range []string{"not executable on this host", "escape", "sysh script", "help"} {
		if !strings.Contains(line, want) {
			t.Fatalf("teaching deny missing %q: %s", want, line)
		}
	}
}

func TestRunPermissiveDeniesBash(t *testing.T) {
	// the runtime denylist closes the permissive-mode hole: bash is
	// structural, not a policy choice
	cfg, _, _, stderr := testConfig(t, strings.Replace(execPolicy, `mode = "enforcing"`, `mode = "permissive"`, 1))
	code := Run(cfg, "/bin/bash -c id")
	if code != 125 {
		t.Fatalf("exit %d, want 125 even in permissive mode", code)
	}
	if !strings.Contains(stderr.String(), "not executable on this host") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestRunConsole(t *testing.T) {
	cfg, _, stdout, stderr, _ := scriptTestConfig(t)
	cfg.Stdin = strings.NewReader("help\n/bin/echo hi\ncd /\n/usr/bin/pwd\nexit\n")
	code := RunConsole(cfg)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"sysh — agent channel",      // banner / MOTD
		"argv is the unit of trust", // help inside the console
		"hi\n",                      // a command ran
		"/tmp",                      // pwd after cd (t.TempDir root)
		"bye",                       // clean exit
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("console output missing %q:\n%s", want, out)
		}
	}
}

func TestRunAgentScriptRecursiveRefused(t *testing.T) {
	cfg, _, stdout, stderr, dir := scriptTestConfig(t)
	p := writeScript(t, dir, "loop.sysh", "#!/usr/bin/sysh\nloop.sysh\n")
	code := Run(cfg, p)
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	if !strings.Contains(stderr.String(), "recursive script") {
		t.Fatalf("stderr = %s", stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunAgentScriptSymlinkEscapeRefused(t *testing.T) {
	cfg, _, _, stderr, dir := scriptTestConfig(t)
	// a symlink inside the dir pointing outside must not run as a
	// script (and its target is not policy-allowed either)
	outside := filepath.Join(filepath.Dir(dir), "outside.sysh")
	os.WriteFile(outside, []byte("#!/usr/bin/sysh\n/bin/echo x\n"), 0o600)
	os.Symlink(outside, filepath.Join(dir, "link.sysh"))
	code := Run(cfg, "link.sysh")
	if code != 125 {
		t.Fatalf("exit %d, want 125", code)
	}
	if !strings.Contains(stderr.String(), "no rule allows this argv") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}
