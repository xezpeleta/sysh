# sysh

**A login shell for AI agents on servers — with a record you can trust.**

When you let an AI agent operate a server, the options are all-or-nothing:
give it a root key (it can do anything, silently), or a normal user (it can
do little, still silently). And even when you *do* let an agent run nearly
unbounded — snapshot-protected, disposable — the question afterwards is
always the same: *"it works, but what else did it do? which files did it
change? which other hosts did it touch?"*

`sysh` makes the agent's SSH login itself the control point. The agent logs
in over plain SSH as an unprivileged system user whose **login shell**:

- **records everything** — every command attempt, allowed or denied, with
  the full argv, the invoking key, and the outcome — to kernel-attested
  logs (journald, auditd) the agent cannot forge or erase;
- **can delimit** — enforce a strict allow-list of exact commands, matched
  on the literal argv with no shell semantics behind it;
- **cannot elevate, ever** — every process it spawns runs under
  `PR_SET_NO_NEW_PRIVS`: setuid and sudo are kernel-disabled for the entire
  agent tree, whatever else lives on the host;
- **waits for humans on root work** — when a command genuinely needs root,
  the agent records a request and stops; a human reviews it *on the server*
  and the human's tool — not the agent — executes it (phase 2).

Control lives **on the server**. Not in the agent's harness, not in prompt
instructions, not in a management plane. The agent cannot talk its way past
a shell.

## What it does

- **Observability first.** One structured event per exec attempt; opt-in
  auditd rules scoped to the agent UID give kernel-level answers to "which
  files were created/modified, which hosts were contacted". Events flow to
  your existing log stack (rsyslog, Wazuh, journal forwarding) for fleet
  correlation.
- **Privilege delimiting.** Policy is a root-owned TOML file: exact argv
  matching with anchored patterns, fixed absolute paths, scrubbed
  environment, per-exec systemd scopes with resource caps. A mandatory
  linter rejects over-broad patterns and known escape-hatch binaries
  (shells, `find`, `xargs`, `tar`, `git`, `ssh`, `docker`, …).
- **Zero elevation surface.** The base install has no sudoers line, no
  setuid helper, no daemon, no tokens — nothing that can raise privileges.
  `no_new_privs` makes that a kernel property for the whole agent process
  tree.
- **Human-gated root work (phase 2).** Approval happens interactively on
  the server: the human sees the host-recorded argv, re-checks it against
  policy, types a confirmation code bound to the *entire* argv, and the
  approve command itself executes it. There is no bearer token to steal,
  replay, or leak.
- **A permissive mode** for snapshot-protected experimentation: the agent
  runs anything it likes — as the unprivileged user, NNP-bit set, every
  argv journaled. Unlimited for the agent, fully recorded for you. Never
  root.

## What it is not

- **Not a sandbox.** The agent operates the real host, as a real
  (unprivileged) user, with the real tools. If you need isolation, run
  `sysh` inside whatever isolation you already have.
- **Not root-without-approval.** If you want an unrestricted root agent,
  `sysh` is not that. The closest it offers is permissive mode plus your
  snapshots.
- **Not monitoring.** It audits its own channel with kernel-attested
  sinks; shipping and correlating events is your existing stack's job.
- **Not an agent or a harness.** It works with any client that speaks SSH
  and passes an argv — scripts, CLI copilots, MCP bridges, humans.
- **Not a replacement for human access.** Your SSH is untouched.

## The whole lifecycle

```console
# sysadmin, on the server (everything local is done by the package):
root@server:~# apt install sysh            # creates the 'sy' user, dirs,
                                           # sshd Match block (validated,
                                           # rolled back on error), optional
                                           # auditd rules

# operator, from their laptop, over plain SSH:
$ ssh-keygen -t ed25519 -f ~/.config/sysh/keys/server.example -C sysh-agent/server.example
$ ssh root@server.example 'sysh auth add' <<< 'restrict ssh-ed25519 AAAA… sysh-agent/server.example'
$ ssh root@server.example 'sysh policy install' < server.example.toml

# anyone the policy allows (human or agent):
$ ssh -i ~/.config/sysh/keys/server.example sy@server.example 'uptime'

# the record:
root@server:~# sysh audit tail
{"key":"sysh-agent/server.example","argv":["uptime"],"decision":"allowed",…}
root@server:~# journalctl -t sysh --since -1h        # kernel-attested
root@server:~# ausearch -k sysh --start today        # files touched, hosts contacted

# a command that needs root (phase 2 design):
$ ssh -i … sy@server.example 'systemctl restart nginx'
approval_required: req_a1b2c3 (report this id; a human must approve it)
root@server:~# sysh approve req_a1b2c3
argv=["systemctl","restart","nginx"]   path=/usr/bin/systemctl
type the pattern-chosen argument: nginx_   # what the policy's patterns matched
[runs as root, in its own systemd unit, result journaled root-side]
$ ssh -i … sy@server.example 'sysh-result req_a1b2c3'
```

Every control operation above is a plain SSH command. There is no daemon,
no API, no management plane to defend, no agent-side anything. One static
binary on the server; the only thing on your laptop is your own ssh (plus,
optionally, a small MCP bridge for agent harnesses, distributed separately).

## Design principles

1. **The server is the enforcement and recording point.** Clients are
   untrusted transport.
2. **argv is the unit of trust.** No shell, no pipes, no `bash -c`, no
   heredocs through the gateway — and argv is printable ASCII only.
3. **No process in the agent tree can gain privileges** — kernel-enforced
   (`no_new_privs`), not configuration-promised.
4. **Approval chooses when; policy chooses what.** Elevation happens only
   inside a root process a human is interactively driving, and never for
   anything the policy forbids.
5. **The agent cannot forge its own record.** Its events carry
   kernel-attested identity (`_UID`, `_PID`, `_EXE`); root-side events live
   where it cannot write.
6. **Audit before everything, fail closed.** If the record cannot be
   written, the command does not run.
7. **`sysh` weakens nothing on the host.** One system user, one scoped
  sshd `Match` block, optional auditd rules — validated and reversible.

## Security properties and honest limits

The threat model, adversary classes, and named residuals are written out in
[PROJECT.md](PROJECT.md). The short version: `sysh` defends against a
**compromised or misbehaving agent** (the `sy` account). It does not defend
against root compromise of the server. Against compromise of the operator's
laptop it is bounded by deployment requirements (the agent harness must run
as a different OS user than your root SSH keys; FIDO2 hardware keys
recommended for root) — and command output flowing to an LLM agent is
externally observable by its provider, which the docs say out loud.

## Status

**Phase 1 implemented.** The specification in [PROJECT.md](PROJECT.md)
has been through two external security review rounds (dispositions in
its §13). What exists today, in this repo:

- **`/usr/bin/sysh`** — one static Go binary, both sides of the system:
  the gateway (login-shell mode, `sysh -c '<command>'`) and the root
  control subcommands (`sysh auth`, `sysh policy`, `sysh audit`,
  `sysh doctor`, `sysh lockdown`).
- **Gateway (§6):** argv-is-the-unit-of-trust parsing (printable ASCII,
  no shell semantics), restricted pattern grammar with linter-computed
  first-character sets (option-injection-proof), deny rules with prefix
  semantics, exact-length allow rules with opt-in `rest`, permissive
  mode (deny rules still apply), builtins (`sy-docs`, `sy-policy`),
  `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` + rlimits + umask 0077,
  scrubbed environment, 1 MiB/stream output cap, timeouts, session-drop
  kill, systemd `--user` scopes with TasksMax/MemoryMax (with fallback),
  lockdown tripwire, and a fail-closed pre-exec journald event — if the
  audit record cannot be written, the exec does not happen.
- **Events (§8):** pure-Go journald sender (`SYSLOG_IDENTIFIER=sysh` +
  structured fields: key id, fingerprint, argv JSON, decision, rule,
  exit, duration, scope, policy SHA-256, mode, phase, truncation), plus
  a `sysh audit tail` viewer. auditd rules for the agent UID ship in the
  deb and install automatically when auditd is present.
- **Control plane (§4.3):** `sysh auth add/list/remove` (restrict-only
  keys, fingerprint-bound ids), `sysh policy install/lint` (mandatory
  linter: denylist on realpath+basename, pattern safety, path ownership
  checks, warning class with per-rule `ack`, permissive-mode auditd
  gate), `sysh doctor` (~20 effective-configuration checks), `sysh
  lockdown`, `sysh journal-group`.
- **Packaging:** `debian/` + `build.sh` produce a self-contained `.deb`
  (user setup, tmpfiles.d, sshd drop-in with `sshd -t` validation and
  rollback, auditd rules with UID substitution, `Match all` terminator).

**Privileged rules (phase 1.5) execute as root via sudo.** A rule with
`privileged = true` runs through an exact-argv `sudo -n` grant that
`sysh policy install` generates into `/etc/sudoers.d/60-sysh` (single
source of truth: the policy) and validates with `visudo -cf` before
activating. The linter enforces the guardrails: `ack = true`, explicit
`timeout`, no `rest`, no whitespace inside argv elements. Events carry
`PRIV=true` and sudo's own journal logging adds a second, independent
record of every root exec. **Honest cost:** the gateway must run
without NoNewPrivs while such a policy is installed (sudo needs
setuid), so the linter also rejects setuid binaries on non-privileged
allow rules in that policy. With zero privileged rules nothing changes.

Phase 2 (approval queue, `sysh-result`, seccomp) and the `sysh-mcp`
distribution are still deferred.

### Build & try it

```sh
make test        # unit tests (pattern analysis, matcher, linter, loader, gateway)
make smoke       # local binary checks (NNP/DUMPABLE selfcheck, fail-closed paths)
make deb         # dist/sysh_<version>_amd64.deb
```

Install on a Debian/Ubuntu host (VM recommended for the first one) —
build the deb yourself, or grab it from the
[releases](https://github.com/xezpeleta/sysh/releases) page:

```sh
sudo apt install ./sysh_*_amd64.deb       # sets up user, dirs, sshd, auditd
sudo sysh auth add                          # paste: restrict ssh-ed25519 AAAA… agent-name
sudo sysh policy install < /usr/share/sysh/policy.example.toml
sudo sysh doctor
```

Then point the agent's SSH client at the `sy` user with the registered
key. Every session is `sysh -c '<command>'`; the agent speaks commands,
the shell speaks policy.

### Honest limits of the current code

- Same-UID tampering: the `sy` user could in principle replace its own
  session's view of files it can write. All gateway-read state
  (policy, keys.map, docs) is root-owned and verified as such at every
  open; `PR_SET_DUMPABLE=0` plus `yama.ptrace_scope>=1` (doctor-checked)
  close the ptrace route.
- The journald socket has no per-message ack: the fail-closed pre-exec
  write detects a dead socket, not journal-side suppression. Drop
  counters are surfaced by `doctor` (`journal drops` check).
- e2e on a real VM (sshd binding, scopes, auditd) is the remaining
  pre-release item; the local suite covers everything up to the sshd
  boundary.

## License

MIT — see `LICENSE`.
