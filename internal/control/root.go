// Package control implements the root-side control subcommands (§4.3):
// auth, policy, audit, doctor, lockdown, journal-group. They are local
// commands invoked by the operator over plain root SSH; the agent
// channel cannot reach them.
package control

import (
	"fmt"
	"io"
	"os"
)

// Paths (production defaults). Vars, not consts, so tests can point
// them at fixtures; production never overrides them (no env vars).
var (
	etcDir       = "/etc/sysh"
	authKeysPath = "/etc/sysh/authorized_keys"
	keysMapPath  = "/etc/sysh/keys.map"
	policyPath   = "/etc/sysh/policy.toml"
	flagsDir     = "/etc/sysh/flags"
	tripwirePath = "/run/sysh-tripwire/lockdown"
	sudoersPath  = "/etc/sudoers.d/60-sysh"

	// ownerUID is the uid that must own the /etc/sysh tree: root in
	// production; tests set it to their own uid.
	ownerUID = 0

	// stdin is where auth add / policy install read operator input.
	stdin io.Reader = os.Stdin
)

// Main dispatches a control invocation. Args exclude the program name.
func Main(args []string) int {
	if len(args) == 0 {
		usage()
		return 64
	}

	cmd := args[0]
	rest := args[1:]

	// version needs no privileges.
	if cmd == "version" {
		fmt.Println(Version)
		return 0
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "sysh %s: control subcommands require root (operator channel)\n", cmd)
		return 1
	}

	switch cmd {
	case "auth":
		return cmdAuth(rest)
	case "policy":
		return cmdPolicy(rest)
	case "audit":
		return cmdAudit(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "lockdown":
		return cmdLockdown(rest)
	case "journal-group":
		return cmdJournalGroup(rest)
	default:
		usage()
		return 64
	}
}

// Version of the sysh binary.
var Version = "0.1.0 (phase 1)"

func usage() {
	fmt.Fprint(os.Stderr, `sysh — login shell for AI agents

usage:
  sysh -c '<command>'              login-shell mode (agent channel, user sy)
  sysh auth add                    register an agent key (stdin: authorized_keys line)
  sysh auth list
  sysh auth remove <key-id>
  sysh policy install [file]       lint + install a policy (default: stdin)
  sysh policy lint [file]
  sysh audit tail [-f]             local view of sysh events
  sysh doctor                      verify effective configuration
  sysh lockdown clear              clear the tripwire
  sysh lockdown status
  sysh journal-group enable|disable  read-only journal group opt-in for sy
  sysh version
`)
}
