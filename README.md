# sysh

**A login shell for unattended AI agents on servers — privilege control
and accountability, enforced on the server itself.**

The name is the mechanism: **sy** — the unprivileged user the agent
logs in as — plus **sh**. Pronounced "sish".

It exists for sysadmin work you let an agent do *alone*: `sysh` bounds
what the agent may do, and records what it actually did. It does not
promise perfect bounds — an allowed command is still a real command —
it promises bounds you set, and a record you can reconstruct the
session from.

And today the options are all-or-nothing: give the agent a root key
(it can do anything, silently), or a normal user (it can do little,
still silently). Even when you let it run nearly unbounded — on a
disposable host, rolled back afterwards — the question afterwards is
always the same: *"it works, but what else did it do? which files did
it change? which other hosts did it touch?"*

`sysh` makes the agent's SSH login itself the control point. The agent
logs in over plain SSH — from any harness, any script, or a plain
terminal — as the unprivileged user `sy`, whose **login shell**
(`sysh`, *sy's shell*) makes every caller learn nothing new:

- **records everything** — every command attempt, allowed or denied, with
  the full argv, the invoking key, and the outcome — to kernel-attested
  logs (journald, auditd) the agent cannot forge or erase;
- **can delimit** — enforce a strict allow-list of exact commands, matched
  on the literal argv with no shell semantics behind it;
- **does not elevate by default** — every process it spawns runs under
  `PR_SET_NO_NEW_PRIVS`: setuid and sudo are kernel-disabled for the entire
  agent tree, whatever else lives on the host. Root work is possible only
  through **operator-written `privileged` rules**: exact-argv sudo grants
  the operator generates and validates at policy install (phase 1.5), or —
  for root work you would rather not pre-authorize — an approval queue a
  human decides per-exec, per request, *on the server* (phase 2).

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
  tree; the only elevation surface is the sudoers fragment `policy install`
  generates, root-owned and limited to the operator's chosen exact argv.
- **No file-transfer side door.** Everything that rides the SSH session
  reaches the same gate: one-off commands, `scp`, `rsync`, even `sftp` —
  sshd executes all of them through the login shell, so moving files is
  policy-checked and recorded exactly like running a command
  (`rsync … sy@host:/path` and a hand-typed `ssh sy@host 'rsync …'` hit
  the identical argv rule). The one exception — an `internal-sftp`
  subsystem, which runs inside sshd itself and bypasses any login shell —
  is detected by `sysh doctor`, which recommends the external
  `sftp-server` (the Debian/Ubuntu default) instead.
- **Human-gated root work (phase 2).** Mark a privileged rule
  `approval = true` and it stops pre-authorizing: each exec becomes a
  request the operator approves from anywhere root SSH reaches
  (`ssh -t root@server sysh approve req_…`). The approver sees the
  host-recorded argv, the approve command re-checks it against policy
  (an operator cannot approve what policy forbids), pattern-chosen
  arguments must be typed by hand, and the approve command itself
  executes from its own in-memory copy in a root systemd scope. The
  agent picks the outcome up read-only (`sysh-result`). There is no
  bearer token to steal, replay, or leak — and the gateway process
  tree stays under `no_new_privs`, because it never elevates.
  For remote/headless operation, bind approval power to registered
  approver keys instead: `sysh approver add` (FIDO2 `sk-*` keys
  recommended — no signature without a touch), then
  `sysh approve <id> --show` → `ssh-keygen -Y sign -n sysh-approve` →
  `sysh approve <id> --sig`. The signature is bound to the exact
  request bytes and the request is single-use and TTL'd.
- **A permissive mode** for controlled experimentation: the agent
  runs anything it likes — as the unprivileged user, NNP-bit set, every
  argv journaled. Unlimited for the agent, fully recorded for you. Never
  root.

## What it is not

- **Not a sandbox.** The agent operates the real host, as a real
  (unprivileged) user, with the real tools. If you need isolation, run
  `sysh` inside whatever isolation you already have.
- **Not root-without-approval.** If you want an unrestricted root agent,
  `sysh` is not that. The closest it offers is permissive mode on a host
  you consider disposable (`sysh` has no snapshot or rollback integration;
  if you want that, snapshot the VM in your hypervisor first — outside
  `sysh`).
- **Not monitoring.** It audits its own channel with kernel-attested
  sinks; shipping and correlating events is your existing stack's job.
- **MCP surface for agent harnesses.** The same .deb ships `sy`, an
  agent-side client: `sy mcp` is a stdio MCP server (Pi, Claude
  Desktop, …) with three tools — `sy_exec`, `sy_docs`, `sy_policy` —
  dialing hosts as the unprivileged `sy` user over SSH with strict
  known_hosts. It has no approval power: an approval-required exec
  surfaces the request id and tells the agent to stop. The matching
  operator command `sy approve <id>` wraps the signing ceremony into
  one step: server-recorded argv display (over your root SSH), YubiKey
  PIN + touch, submit.
- **A live wall of what agents are doing.** `sy watch` is the
  operator-side counterpart: one read-only `journalctl -t sysh -f`
  follow per configured host, over the same root SSH channel, rendered
  as a localhost web view — every exec attempt, decision, and pending
  approval across all hosts, live. A pending request is one click from
  answered, two ways: *approve here* runs the whole ceremony in the
  page — the argv is fetched from the server when the modal opens, a
  typed argument proves you read it, and the token touch happens
  inside `ssh-keygen` — and *run in terminal* opens a terminal with
  `sy approve` already running. (`--no-challenge` drops the typed
  argument for touch-only confirmation; the default keeps it.) The argv shown is the argv signed;
  the browser is the renderer, like a terminal emulator. Same-origin
  only (`Sec-Fetch-Site` + JSON), loopback-only, rate-limited; no
  daemon and no listener on any managed host — the journal stays the
  only source of truth.
- **Not an agent or a harness.** It works with any client that speaks SSH
  and passes an argv — scripts, CLI copilots, MCP bridges, humans.
- **Not a replacement for human access.** Your SSH is untouched.

## Two phases: attended setup, unattended operation

`sysh` splits agent work on a server into two very different modes.

**Attended preparation.** A human with root SSH — often working *with* a
code agent at their side — prepares the host: install the deb, write the
policy, create the file-access shape the policy assumes (groups, ACLs,
ownership, traverse-only directories), deploy the agent key, and run
`sysh doctor` until it is clean. In this phase the code agent is an
assistant to the operator, not autonomous: every root action is
supervised, interactive, and reversible (work on a VM you can snapshot —
`sysh` itself has no rollback). A worked example — an agent-maintained
web server: read the Apache config tree and logs, write the enumerated
config files, validate, reload — is spelled out in
[`examples/webserver/`](examples/webserver/).

**Unattended operation.** Once the host is prepared, the agent connects
as `sy` over plain SSH and works alone inside the bounds the operator
set: the exact-argv policy, the OS-level permissions beneath it,
`no_new_privs`, per-exec scopes and caps, and journald/auditd recording.
No human watches each command; the journal is the watch.

The honest framing: **these bounds are not infallible, and do not need
to be.** An allowed argv is still a real program with real behavior —
`tee` writes whatever the agent pipes into the file it was granted, and
a bug in an allowed binary is reachable. What exact-argv matching plus
OS permissions buy you is *bounded, recorded, root-free-by-default*
agent access — enough to make unattended AI-agent use on real servers
defensible, where the alternatives are "give it a root shell" or "no
agent at all". The record (sysh events, auditd, sudo's own journal
line) is what lets you reconstruct afterwards what the agent actually
did, and the phase-2 approval gate covers root work you did not
pre-authorize.

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

# a command that needs root — operator pre-authorized it as a
# privileged rule (phase 1.5: exact-argv sudo grant, PRIV event, and
# sudo's own journal line as a second record):
$ ssh -i … sy@server.example 'systemctl restart nginx'
[runs as root via sudo, events carry PRIV=true]

# root work the operator did NOT pre-authorize (phase 2: approval rule):
$ ssh -i … sy@server.example 'systemctl restart postgresql'
{"sysh":1,"class":"approval_required","request_id":"req_a1b2c3d4e5f6",…}
(report the request id and stop — nothing has run)

# the operator, from anywhere root SSH reaches:
root@server:~# sysh approvals
req_a1b2c3d4e5f6  age=12s  key=agent/server.example
  argv=["/usr/bin/systemctl","restart","postgresql"]
root@server:~# sysh approve req_a1b2c3d4e5f6
  argv:   ["/usr/bin/systemctl","restart","postgresql"]
  execute as root? [yes/no] yes
type argument 2 exactly as shown (postgresql): postgresql
executed: exit=0 in 213ms; the agent fetches the outcome with: sysh-result req_a1b2c3d4e5f6

# the agent, read-only:
$ ssh -i … sy@server.example 'sysh-result req_a1b2c3d4e5f6'
[approved command output; exit status passes through]'
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

The phase-2 approval queue is implemented (gateway request flow,
`sysh approvals` / `sysh approve` / `sysh deny`, `sysh-result`). Still
deferred: the YubiKey-signed and Telegram-bot approval transports (both
front-ends of the same `sysh approve` primitive), the seccomp read-only
profile, and the `sysh-mcp` distribution.

**Operator-side tooling lives in the `sy` client:** `sy mcp` (agent
bridge), `sy approve` / `sy approvals` (ceremony and queue), and
`sy watch` — the localhost, read-only web viewer that follows every
host's sysh journal over root SSH and shows pending approvals with
the exact command to answer them where the ceremony lives. It ships no
`sysh`-server changes: it is pure client.

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
