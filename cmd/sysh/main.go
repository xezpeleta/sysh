// sysh — a login shell for AI agents on servers.
//
// Dispatch (§3.2): the sy user's login shell is invoked by sshd as
//
//	sysh -c '<command>'
//
// for every agent channel session. All other invocations are the
// operator's local control commands (root only) or errors.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/xezpeleta/sysh/internal/control"
	"github.com/xezpeleta/sysh/internal/gateway"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]

	// Containment self-check (used by packaging and doctor): applies
	// NNP via re-exec and verifies the kernel-visible bits.
	if len(args) == 1 && args[0] == "selfcheck" {
		return selfCheck()
	}

	// version is unprivileged, read-only.
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(control.Version)
		return 0
	}

	// Gateway mode: `sysh -c '<command>'`, only meaningful for the
	// agent channel user. We do not hard-require the sy user (the
	// doctor and packaging enforce that binding; tests and dev hosts
	// may run other uids), but root must never land here: a root
	// account whose shell is sysh would be a misconfiguration.
	if len(args) >= 2 && args[0] == "-c" {
		if os.Geteuid() == 0 {
			fmt.Fprintln(os.Stderr, "sysh: refusing gateway mode as root (the agent channel must use the unprivileged sy user)")
			return 125
		}
		return gatewayMain(args[1])
	}

	// Non-root invocations that are not `-c` are protocol violations:
	// the agent channel may only speak `sysh -c '<command>'` — with
	// two exceptions, both still the unprivileged gateway:
	if os.Geteuid() != 0 {
		if len(args) == 0 {
			// Interactive console (§6.11): `ssh sy@host` with no command
			// and a TTY attached. The banner is the MOTD; each line is a
			// policy-checked exec like any other.
			if stdinIsTTY() {
				return consoleMain()
			}
			fmt.Fprintln(os.Stderr, `{"sysh":1,"class":"no_input","detail":"interactive logins are not supported; the agent channel speaks `+"`sysh -c '<command>'`"+` only","exit":3}`)
			return 3
		}
		// Script interpreter (§6.10): the kernel execs `sysh <script>`
		// when the shebang says #!/usr/bin/sysh (an operator script
		// allowed by an exact rule).
		if len(args) == 1 {
			if fi, err := os.Stat(args[0]); err == nil && fi.Mode().IsRegular() {
				return scriptMain(args[0])
			}
		}
		fmt.Fprintf(os.Stderr, `{"sysh":1,"class":"malformed","detail":"unexpected gateway invocation: %v","exit":3}`+"\n", args)
		return 3
	}

	// Control mode.
	return control.Main(args)
}

// gatewayMain performs the containment preamble (NNP re-exec, DUMPABLE,
// rlimits, umask) and then runs one gateway invocation. The NNP re-exec
// lives here — not inside gateway.Run — so tests calling gateway.Run
// never re-exec the test binary.
func gatewayMain(cmd string) int {
	if code := gatewayPreamble(); code != 0 {
		return code
	}
	return gateway.Run(gateway.ProdConfig(), cmd)
}

// scriptMain is the interpreter entry point (§6.10).
func scriptMain(path string) int {
	if code := gatewayPreamble(); code != 0 {
		return code
	}
	return gateway.RunScriptFile(gateway.ProdConfig(), path)
}

// consoleMain is the interactive entry point (§6.11).
func consoleMain() int {
	if code := gatewayPreamble(); code != 0 {
		return code
	}
	return gateway.RunConsole(gateway.ProdConfig())
}

// gatewayPreamble applies the containment bits shared by every
// gateway entry (-c, script, console). Fail closed: any setup error
// refuses the session.
func gatewayPreamble() int {
	cfg := gateway.ProdConfig()

	// NoNewPrivs is skipped only when the installed policy declares
	// privileged rules: sudo needs setuid to honor their exact-argv
	// grants. Fail closed — any load error keeps NNP on, and a policy
	// without privileged rules always gets NNP (§6.7).
	if !gateway.PolicyUsesPrivileged(cfg.PolicyPath, cfg.PolicyOwner) {
		if err := gateway.EnsureNNP(); err != nil {
			fmt.Fprintf(os.Stderr, `{"sysh":1,"class":"internal_error","detail":"NNP setup failed: %s","exit":125}`+"\n", err)
			return 125
		}
	}
	if err := gateway.SetDumpable(); err != nil {
		fmt.Fprintf(os.Stderr, `{"sysh":1,"class":"internal_error","detail":"PR_SET_DUMPABLE failed: %s","exit":125}`+"\n", err)
		return 125
	}
	if err := gateway.ApplyResourceLimits(); err != nil {
		fmt.Fprintf(os.Stderr, `{"sysh":1,"class":"internal_error","detail":"rlimits failed: %s","exit":125}`+"\n", err)
		return 125
	}
	gateway.Umask0077()
	return 0
}

// stdinIsTTY reports whether stdin is a terminal (the interactive
// console only exists on a real TTY — piped stdin stays the -c-only
// protocol).
func stdinIsTTY() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// selfCheck applies and verifies the containment bits.
func selfCheck() int {
	if err := gateway.EnsureNNP(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL NoNewPrivs: %v\n", err)
		return 1
	}
	if err := gateway.SetDumpable(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL DUMPABLE: %v\n", err)
		return 1
	}
	fmt.Println("ok    NoNewPrivs: 1, Dumpable: 0")
	return 0
}
