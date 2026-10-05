# sysh — Project Specification

Status: **design v3, pre-implementation.** Incorporates two external
security review rounds (dispositions in §13). No prior prototypes are
assumed; the document is self-contained.

---

## 1. Purpose and scope

`sysh` lets an operator delegate server work to an automated agent (a script,
an LLM-driven CLI, an MCP client) over normal SSH — with a trustworthy record
of everything the agent did.

The problem: operators increasingly let agents operate real servers, and the
options are all-or-nothing. A root key is unacceptable; a normal user is
unaudited in any agent-specific way; and even when an agent *is* given broad
power (broad, throwaway-host experimentation is a legitimate workflow), the
operator's first question afterwards — *"it works, but what else did it do?
which files did it change? which other hosts did it touch?"* — has no answer.

`sysh` makes the agent's login itself the control point. The agent's account
is an unprivileged system user whose login shell:

- **records everything** — every exec attempt, allowed or denied, with the
  full argv, the invoking key, the decision, and the outcome, to
  kernel-attested sinks the agent cannot forge;
- **can delimit** — enforce a strict allow-list of exact commands (argv
  matching, no shell semantics, fixed absolute paths, scrubbed environment);
- **elevates only what the operator wrote down, one argv at a time** —
  by default no process in the agent's tree can gain privileges
  (`PR_SET_NO_NEW_PRIVS`, kernel-enforced). Root work needs a
  `privileged = true` rule: `policy install` then generates an exact-argv
  sudoers grant (phase 1.5, §6.8) — root power, but only for argv the
  operator pre-authorized, doubly recorded (gateway event with `PRIV=true`
  plus sudo's own journal line). Per-command human approval remains the
  phase-2 design (§9).

Phase 1 delivered the record and the delimiting. Phase 1.5 added
operator-pre-authorized root exec through generated sudo grants. Phase 2
(§9) added per-exec operator-gated root: `approval = true` rules that
pre-authorize nothing and queue a request instead.

### 1.1 Naming (settled)

One syllable, three referents:

| Thing | Name | |
|---|---|---|
| server user | `sy` | default account the agent logs in as |
| login shell / project | `sysh` | *sy's shell* — what /etc/passwd says |
| laptop-side client | `sy` | one binary: `sy mcp` (stdio MCP server), later `sy provision`, `sy doctor` |

`sy runs sysh` is the whole story, and it is literal. The name collision
space was checked before settling: `shy` is taken by an existing AI-agent
sandbox (Shai, pronounced "shy"), `aish` by an AI-assisted SSH shell;
`sysh` is clean (only a Spotify dashboard, different space).

Positioning, in one sentence: **the control point is the shell itself** —
whatever sends commands over SSH (any harness, any script, a junior admin)
gets the same bounds and the same record, without learning new commands;
sysh is not a harness and does not want to be one.

The account name is **not** part of the trust model (identity is the
key id + the account's uid; enforcement never consults the name), so it
is configurable at install time (`SYSH_USER=…` to postinst →
`/etc/sysh/user`, sshd `Match` generated from it), defaulting to `sy`.
Nothing about enforcement changes when it is renamed.

## 2. Non-goals

- **Not a sandbox.** The agent runs real commands on the real host as a real
  unprivileged user. No chroot, namespaces, or microVMs.
- **Not unrestricted root — with one loud, named exception.** `sysh`
  root power is a closed list of exact argv the operator wrote into a
  `privileged` rule — never a shell, never `rest`, never a pattern. For
  unstructured room there are two honest options: *permissive mode*
  (§6.6) — unlimited as the unprivileged `sy` user, fully recorded —
  and *root mode* (§6.9), the explicit opt-out for total freedom on a
  host you consider disposable. Root mode is freedom with a journal,
  not control; `sysh` never pretends otherwise. (Rollback, if you want
  it, is your own hypervisor/backup practice; `sysh` has no snapshot
  integration.)
- **Not monitoring or a SIEM.** `sysh` emits structured, attributable events
  (journal, auditd); shipping and correlating them is your existing stack's
  job.
- **Not an agent framework.** No prompting, no planning. Any SSH client works.
- **Does not manage human access.** Operator SSH untouched; `sysh` adds one
  system user, one `Match` block scoped to that user, and nothing else by
  default.
- **Does not defend against root compromise** of the server, by definition.

## 3. Architecture

**Implementation language: Go.** Chosen deliberately: a statically linked
single binary with no runtime dependencies on servers; the RE2 regexp
engine (linear-time, no backtracking) that the pattern grammar of §6.2
requires; direct `prctl`/syscall control for `PR_SET_NO_NEW_PRIVS` and
`PR_SET_DUMPABLE`; and trivial cross-compilation for deb packaging.

One static Go binary on the server, behaving by role:

```
┌────────────────────────────── server ─────────────────────────────────┐
│                                                                       │
│ sshd (Match user=sy) ── exec ──> sysh -c '<argv…>'     uid=sy         │
│    │                                    │ policy check (root-owned)   │
│    │ ExposeAuthInfo                     │ PR_SET_NO_NEW_PRIVS         │
│    ▼ (key fingerprint)                  │ systemd-run scope per exec  │
│  /etc/sysh/keys.map (root)              │ env scrub, rlimits, cgroup  │
│                                         ▼                             │
│    child runs as unprivileged sy, NNP-bit set — or, for a           │
│    privileged rule, as root via the operator's exact-argv sudo       │
│    grant (NNP off for that gateway, §6.8)                           │
│                                         │                             │
│                            journald ← every decision, kernel-attested │
│                              (_UID/_PID/_EXE — sy cannot forge)       │
│                                                                       │
│  [opt-in, phase 1] auditd: UID-scoped execve / write / connect rules  │
│                                                                       │
│  [phase 2] root, interactive:                                         │
│     sysh approve req_…  → re-check policy → systemd-run as root       │
│     sysh-result req_…   → agent fetches read-only outcome            │
│                                                                       │
│  /etc/sysh/  (root-owned 0644/0600): authorized_keys, keys.map,       │
│              policy.toml, docs/                                       │
│  /run/sysh/requests/ (root:sy 1730 drop box; untrusted; phase 2)     │
│  /run/sysh/  (root-owned; results root:sy 0750; tmpfiles.d)          │
│  /run/sysh-tripwire/ (world-writable, sticky): lockdown only          │
└───────────────────────────────────────────────────────────────────────┘
        ▲                                     ▲
        │ ssh, per-host agent key             │ ssh, operator's own key
        │ (agent channel, untrusted)          │ (control channel, root)
   any SSH client                         human operator
```

Trust boundaries:

- **Agent channel** (`sy@`): fully untrusted; everything it touches is
  enforced or verified host-side.
- **Control channel** (`root@`): the operator's own SSH, out of `sysh`'s
  scope. All control operations (`sysh auth add`, `sysh policy install`,
  `sysh approvals`, `sysh approve`, `sysh doctor`, `sysh audit`) are local
  commands invoked over it.
- **Load-bearing property:** the `sy` UID cannot elevate (NNP), cannot
  rewrite its policy, keys, key map, or any root-side state, and cannot
  forge its audit record. Every design decision below serves this.

## 4. Deployment

### 4.1 Package

A single deb `sysh` shipping exactly one static binary, `/usr/bin/sysh`,
plus docs. No daemon, no socket, no service, no setuid, no sudoers. Hard
dependency: systemd (exec scopes, journald). Optional: auditd (§8.4).

The laptop-side MCP bridge (`sysh-mcp`) is a **separate distribution** — it
runs in a different trust domain (§10).

### 4.2 postinst (transactional, idempotent)

1. Create system user `sy` (home `/var/lib/sysh`, root-owned, non-writable
   by `sy`; shell `/usr/bin/sysh`). **If a `sy` user pre-exists, verify it
   has no supplementary groups** (`sudo`, `adm`, `docker`, …); refuse with a
   clear error if it does.
2. Create `/etc/sysh/` (root:root 0755). `/run` is a tmpfs, so the
   volatile state is declared via **tmpfiles.d** and recreated at boot,
   not by postinst: `/run/sysh/` (root:root 0755; phase-2 results as
   root:sy 0750 so other local users cannot read root output) and
   `/run/sysh/requests/` (root:sy 1730, sticky — a **drop box**: `sy` may create
   files but not list the directory), plus `/run/sysh-tripwire/`
   (1777, sticky). The request spool is intentionally volatile: requests
   are TTL'd at 10 minutes and must not survive a reboot.
3. Install the sshd drop-in (§5.3). Validate with `sshd -t` before reload;
   **roll back on failure** — a bad drop-in must never lock out admins (P7).
4. debconf: enable auditd integration? (default yes if auditd present)
   → install UID-scoped rules (§8.4).
5. debconf (default no): add `sy` to a **read-only journal group**
   (`systemd-journal` only — never `adm`, `docker`, `sudo`) so operators
   can read `sysh` events without root. The no-supplementary-groups
   check in `doctor` knows two opt-ins: this one (flag-gated), and any
   group the operator declares in `/etc/sysh/flags/allowed-groups` —
   the mechanism for file-access groups that back policy profiles
   (e.g. rw on a single config file, §6.8); undeclared groups fail.
6. `purge` removes the user, `/etc/sysh`, the sshd drop-in, the auditd
   rules, and the tmpfiles.d entries. Audit history in the journal is
   intentionally kept. The spool, being volatile, disappears with the
   reboot. Nothing under `/var` is left.

No keys are generated at install time (nothing is signed — §12), so cloned
images and golden templates are safe.

### 4.3 Operator onboarding (plain SSH, no orchestrator)

```console
$ ssh-keygen -t ed25519 -f ~/.config/sysh/keys/server.example -C sysh-agent/server.example
$ ssh root@server.example 'sysh auth add' <<< 'restrict ssh-ed25519 AAAA… sysh-agent/server.example'
$ ssh root@server.example 'sysh policy install' < server.example.toml
```

`sysh auth add` (root): parses the line with a real parser
(`ssh.ParseAuthorizedKey`), **requires `restrict` or the full console
set** (`no-X11-forwarding,no-agent-forwarding,no-port-forwarding,
no-user-rc` — restrict minus `no-pty`, §6.11), rejects embedded
newlines and any other option (command/pty/forwarding/agent access),
optionally requires `from=` (configurable), computes the key fingerprint,
prompts for a key ID, and writes both the line (`/etc/sysh/authorized_keys`,
root:root 0644 — sshd reads AuthorizedKeysFile as the target user) and
`fingerprint → key-id` into `/etc/sysh/keys.map` (root:root 0644 — the
mapping is not secret, and the gateway must be able to read it).

## 5. Identity and keys

- **Agent keys**: ordinary per-host Ed25519 keys on the operator side
  (`~/.config/sysh/keys/<host>`); the host never sees private material.
  Revocation = remove the line from `authorized_keys`.
- **Key identity at exec time**: the sshd `Match` block sets
  `ExposeAuthInfo yes`; sshd writes the accepted-key details to a
  per-session file (`$SSH_USER_AUTH`) which the shell reads to obtain the
  **fingerprint**. The displayed key ID comes from the root-owned
  `keys.map`. Identity in audit events is therefore kernel/sshd-derived,
  not agent-claimed. (Implementation note: verify on the target OpenSSH
  whether the `$SSH_USER_AUTH` file is user-owned; the gateway reads it
  first thing, before any child could tamper, and `doctor` cross-checks
  against sshd's own `Accepted publickey … SHA256:…` log line.)
- **Operator root access**: the operator's own SSH keys. **Recommended:
  FIDO2 hardware-backed keys (`ed25519-sk`).** Deployment requirement DR1
  (§10/§11) covers separation from the agent harness.
- Host-key verification on the operator side is stock `known_hosts`
  semantics. `sysh` adds nothing there.

### 5.3 sshd drop-in

Scoped to `Match user sy`:

```
AuthorizedKeysFile /etc/sysh/authorized_keys
AuthenticationMethods publickey
DisableForwarding yes
PermitTTY yes
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserRC no
ExposeAuthInfo yes
```

`PermitTTY yes` (§6.11): a PTY reaches only the gateway — the
confinement — where every console line is policy-checked. Set it to
`no` to keep the agent channel `-c`-only.

`sysh doctor` verifies the **effective** configuration with
`sshd -T -C user=sy,host=<host>,addr=<addr>` (sshd is first-match-wins and
`Include` support varies by distro) and fails on any drift.


#### What flows through the login shell (verified)

OpenSSH `session.c` executes every *exec* request through the user's login
shell — `execve(shell, {shell, "-c", command})` — and routes *external*
subsystem requests through the same path (`do_exec(ssh, s, subsystem_args)`).
Verified live on a stock Debian 12 host by installing a logging shell as a
test account's login shell and connecting with each client:

| client                    | what the login shell receives                          |
|---------------------------|--------------------------------------------------------|
| `ssh host cmd`            | `-c '<cmd>'`                                            |
| `ssh host` (shell request)| `argv[0] = -<shell>` (login form, no `-c`)              |
| `scp` (upload / download) | `-c 'scp -t <dir>'` / `-c 'scp -f <file>'`              |
| `rsync`                   | `-c 'rsync --server <flags> . <path>'`                  |
| `sftp` (external binary)  | `-c '/usr/lib/openssh/sftp-server'`                     |

Consequences:

- **File-transfer tools cannot sidestep the argv policy.** An operator
  scoping a `rsync --server …` or `scp -f …` rule is scoping file movement
  itself; a transfer the policy does not name is denied and recorded like
  any other command. Verified end-to-end against a production sysh
  install: `scp`, `rsync` and `sftp` sessions as `sy` all produced normal
  `deny` events with their full remote-side argv.
- **`internal-sftp` is the one exception**: it runs in-process inside
  sshd (`sftp_server_main()`), never reaching any login shell, and
  `Subsystem` cannot be restricted per-`Match`. Doctor therefore resolves
  the effective subsystem via `sshd -T` and warns when it is
  `internal-sftp` (recommendation: the external `sftp-server` binary,
  which the Debian/Ubuntu default already uses, so the default posture
  needs no change).

## 6. Gateway semantics (`sysh` as login shell, uid=sy)

### 6.1 argv is the unit of trust

sshd execs the shell as `sysh -c '<command string>'`. `sysh`:

- splits the string on whitespace with **no** shell semantics — no
  expansions, globbing, quoting, or metacharacter interpretation
  (`a; b`, `a | b`, `$(x)` are literal words that match no sane rule);
- **rejects any argv containing non-printable-ASCII bytes** (exit 3) —
  defeating terminal-escape / bidi-override / homoglyph attacks in later
  displays, and making hashing and logging unambiguous;
- treats the resulting argv as the request.

### 6.2 Matching (hardened)

Per rule, each position is either a literal or a **pattern** from a
restricted grammar — literals, alternation, and character classes only
(no backreferences, lookaround, or unbounded repetition) — compiled with
Go's RE2 (linear time) and anchored `\A…\z`. From the syntax tree the
linter computes the pattern's first-character set and rejects anything
that can match a leading `-` (no option injection). Examples:
`"nginx|apache"`, `"[a-z0-9@._][a-z0-9@._\\-]*"` (leading class without
`-`). One exception, learned live: some protocols pass option clusters
as fixed argv positions by design (`rsync --server` sends its protocol
flags as one token). A fixed-position pattern that can match a leading
`-` is allowed when the rule carries `ack = true` — the operator wrote
that cluster themselves; `rest` positions can never match one, ack or
not.

- **Exact length by default**: extra arguments are denied. Opt-in
  `rest = "<pattern>"` allows additional positions, each matching that
  anchored pattern.
- **All deny rules are evaluated first**, with **prefix semantics**: a
  deny matches if its positions match the argv's leading positions, so
  `deny ["find"]` refuses `find` with any arguments. Then the first allow
  match wins (allow rules stay exact-length, §6.2).
- Rules carry an absolute `path` to the binary (no `PATH` search); the
  linter verifies existence, root ownership, and that neither the binary
  nor any ancestor directory is group/world-writable.
- Execution environment is fixed: minimal scrubbed env (no `LD_*`, no
  `PAGER`/`SYSTEMD_PAGER`/`GIT_*`/`LESSOPEN`; fixed `PATH`, `HOME`,
  `TERM=dumb`), `cwd=/var/lib/sysh`, `umask 077`, rlimits on file
  descriptors and processes, stdin/stdout/stderr only.

### 6.3 Builtins (always allowed, read-only)

- `sy-docs` — dump `/etc/sysh/docs/*.md` (operator-maintained host
  knowledge; discoverability is the difference between an agent that asks
  and one that guesses).
- `sy-policy` — dump the effective policy.
- `sysh-result <req>` — fetch the outcome of an approved request
  (read-only, TTL'd; 31 = pending/expired/never approved).
- `help` — the protocol explains itself (§6.10): the contract, the
  script directory in force, the honest limits. Journaled as a
  builtin event like the others.

### 6.4 Result reporting

Every terminal outcome writes **one structured line to stderr** (JSON:
class, detail, request id where applicable, key id). This is the
authoritative machine-readable contract. The process exit code is kept as
human convenience only: child exit statuses pass through when a child ran;
gateway refusals use a documented set (2 lockdown, 3 malformed argv, 30
approval required (30), 125 denied, 31 no result) —
with the explicit caveat that these collide with child codes (`systemctl
status` returns 3; `timeout` uses 124), which is exactly why automation
must read the stderr line.

**Channels are separated by design**: the child's stdout streams to
the session's stdout **untouched**, and the envelope goes to stderr —
so an agent parses command output from stdout as it always would and
reads stderr for the outcome (class, exit, rule). A remote pipe like
`cmd | grep x` is denied with a teaching line ("no shell operators
here — send one command per exec"): there is no shell to interpret
it, and filtering belongs on the caller's side (`ssh sy@host 'cmd'
| grep x` runs the pipe in the agent's own shell) — or inside a
traced script, where every side of the pipe is a checked exec
(§6.13). The `help` builtin states this contract in-band.

### 6.5 Lockdown

Any local user may create `/run/sysh-tripwire/lockdown` (a tripwire: an
agent that notices compromise can lock its own channel). While present, all
agent-channel exec is refused (exit 2). Only root clears it, by fixed name. More
generally, root code never opens or follows paths inside `sy`-writable
directories — with one narrow, fully specified exception: the phase-2
request spool, read only through the safe pattern of §9 (`openat` with
`O_NOFOLLOW|O_NONBLOCK`, regular-file and `st_nlink == 1` checks, size
caps).

### 6.6 Permissive mode

A policy may set `mode = "permissive"`: every well-formed argv (still
ASCII-checked, still NNP, still scoped and journaled) runs as the
unprivileged `sy` user; the OS's own permissions are the only limit. This
serves the "give it room, keep the record" workflow on a host you can
afford to lose (rolling such a host back is the operator's own
hypervisor/backup practice, outside `sysh`) —
understood honestly as **arbitrary code as `sy` on a host you consider
disposable**: it can reach local services, world-readable secrets, other
hosts, and (on cloud VMs) the instance metadata endpoint. It never grants
root; `privileged` rules in permissive mode are a lint error
(root-equivalent exec must not be possible while anything else runs
unchecked).

Two consequences follow:

- **auditd integration (§8.4) is mandatory in permissive mode** —
  `policy install` refuses a permissive policy when the UID-scoped rules
  are not active. With arbitrary code running as `sy`, journald events
  alone are not a trustworthy record (R4/R7); auditd is the kernel-level
  source that survives gateway tampering.
- On cloud hosts with a metadata endpoint, an nftables/iptables
  **owner-match rule blocking that endpoint for the `sy` UID** can be
  installed alongside the auditd rules (documented, opt-in). On-prem VMs
  without a metadata service need nothing.

Persistence hygiene (both modes): code that outlives its session
(`crontab`, `at`/`batch`, user systemd units, lingering) escapes both NNP
and the gateway's logging. In enforcing mode the linter denies those
tools (§7); in any mode `doctor` verifies `Linger=no` for `sy`, an empty
crontab, and `cron.allow`/`at.allow` excluding `sy` — tripwires, not
walls.

### 6.7 Process containment

Every child exec:

- runs under `PR_SET_NO_NEW_PRIVS` (set before any thread spawns, or via
  re-exec — the flag is per-thread in Linux). Setuid and sudo become
  unusable for the entire agent tree, on both tiers, regardless of host
  configuration. "No elevation surface" is a kernel property, not a claim
  about config files. **Exception, phase 1.5:** a policy containing
  `privileged` rules is the one sanctioned elevation surface — the gateway
  then starts *without* NNP (sudo needs setuid) and the linter refuses
  setuid binaries on non-privileged allow rules in such a policy, so no
  other path to setuid exists. With zero privileged rules nothing changes.
- the gateway itself calls `prctl(PR_SET_DUMPABLE, 0)` at startup, so
  same-UID processes cannot `ptrace` it or write its `/proc/<pid>/mem`
  (children re-enable dumpable on exec). `doctor` checks
  `kernel.yama.ptrace_scope >= 1` and warns otherwise.
- runs inside a transient systemd scope of the **user manager**
  (`systemd-run --user --scope --unit sysh-<sanitized-keyid>-<seq>`; key
  IDs are reduced to `[a-z0-9-]` before use in unit names), giving journal
  attribution, `TasksMax`, `MemoryMax`, and kill-the-whole-cgroup on
  timeout. This needs `UsePAM yes`, a running `user@<uid>.service`, and
  cgroup delegation of `memory`/`pids`; `doctor` verifies all three, and
  the gateway falls back to a plain subprocess (no scope, still NNP) with
  `scope=false` marked in the event.
- has output capped; on timeout the scope is killed (exit 124), and when
  the SSH session drops the gateway kills the scope too (SIGHUP/SIGPIPE)
  so nothing outlives its session. **Privileged children (phase 1.5):**
  the user manager runs as uid `sy` and *cannot signal root processes*
  (verified live: `EPERM`), so privileged timeouts are enforced by the
  sudoers `TIMEOUT=<rule timeout>` tag — sudo, running as root, kills its
  own child — and the gateway waits a short grace for sudo to exit before
  killing the scope, so killing sudo first cannot orphan the root child.

Multiple agent keys share one UID: key identity is **attribution, not
isolation** (R4).

### 6.8 Privileged execution (phase 1.5)

A rule with `privileged = true` runs as root, through sudo, under
guardrails that keep the argv list closed:

- **The grant is generated, never hand-written.** `sysh policy install`
  renders `/etc/sudoers.d/60-sysh` (0440 root:root) from the policy —
  one `sy ALL=(root) TIMEOUT=<n> NOPASSWD: <argv>` line per privileged
  rule, prefixed with `Defaults:sy !setenv` — validates it with
  `visudo -cf` *before* writing anything, and removes the fragment when
  the last privileged rule disappears. The policy is the single source
  of truth; drift is a doctor failure.
- **sudo ≥ 1.9.13 is required** (per-command `TIMEOUT`, the only
  reliable privileged-timeout enforcer — see §6.7). `policy install`
  refuses otherwise.
- **The gateway wraps the exec**: `[sudo, -n, --, <path>, <args…>]`,
  still inside the systemd scope, still output-capped, env still
  scrubbed. `-n` means a missing grant fails rather than prompting.
- **Double record**: sysh events carry `PRIV=true` with the agent's
  argv, key id, and rule index; sudo's own journal entry (invoking uid,
  command, tty) is written by a different code path the agent cannot
  influence.
- **Linter guardrails**: `ack = true` and an explicit `timeout` are
  mandatory; `rest` and whitespace inside argv elements are forbidden
  (sudoers grants are exact argv strings); permissive mode +
  privileged is refused outright; setuid binaries on non-privileged
  allow rules are refused while any privileged rule exists (NNP is off,
  so nothing else may reach setuid).
- **Honest cost**: while such a policy is installed the gateway starts
  without NoNewPrivs. That is the whole trade: containment is weakened
  to exactly the operator's chosen argv, observability stays total.

## 7. Policy

TOML, human-authored, root-installed:

```toml
version = 2
host = "server.example"
mode = "enforcing"            # or "permissive" (§6.6)

[[rule]]
argv = ["uptime"]
path = "/usr/bin/uptime"

[[rule]]
argv = ["systemctl", "status", "[a-z0-9@._\\-]+"]
rest = "[a-z0-9@._\\-]+"
path = "/usr/bin/systemctl"
timeout = 10

[[rule]]
argv = ["find", "/var/log"]
deny = true

[[rule]]
argv = ["systemctl", "restart", "nginx|apache"]
path = "/usr/bin/systemctl"
privileged = true             # executed as root via the operator's
                              # exact-argv sudo grant (§6.8); ack and an
                              # explicit timeout are mandatory
```

- `sysh policy install` (root) **runs the linter and refuses on any
  finding**; `sysh doctor` re-lints installed policies.
- The linter (v1, mandatory): pattern safety (anchored, cannot match a
  leading `-`, cannot match empty — via the first-character set of the
  restricted grammar, §6.2), path checks (§6.2), and a package-maintained
  **escape-hatch denylist** — shells and interpreters (`sh`, `bash`,
  `python*`, `perl`, `ruby`, `node`, `awk`, …), argv passthrough /
  execution wrappers (`env`, `nohup`, `setsid`, `stdbuf`, `timeout`,
  `nice`, `xargs`, `find`, `tar`, `git`, `systemd-run`), remote and
  privileged tools (`ssh`, `scp`, `sftp`, `nc`, `socat`, `docker`,
  `podman`, `sudo`, `su`, `mount`), pagers/editors (`less`, `vi*`, …),
  and persistence tools (`crontab`, `at`, `batch`, `systemctl --user`,
  `busctl`). The denylist matches the **realpath and basename** of each
  rule's `path` — not `argv[0]` — so aliases and versioned names
  (`python3.11`, `view`, `busybox`) cannot slip past. Binaries that write
  files or open network connections without being executors (`curl`,
  `wget`, `rsync`, …) raise a **warning** that requires an explicit
  `ack = true` on the rule before `policy install` proceeds. `ack = true`
  is rule-scoped review: it acknowledges **all** of that rule's warnings
  (never errors). Over-broad
  rules are the most likely real-world failure; the linter is the
  countermeasure, not an afterthought.
- Loading: open once, `fstat` ownership/mode of file and ancestors, parse
  **that same buffer** (no re-open TOCTOU). Fail closed (all exec denied,
  stderr line explains) on any anomaly.
- The `sy` UID cannot write `/etc/sysh`; no signature scheme is used — §12
  explains why it was removed.

Worked examples ship in [`examples/`](examples/), each with its own
README and an installable policy: **`diagnostic/`** (read-only — 59
rules over the observe verbs, read-only-ness by omission: no mutating
tool has a rule), **`operational/`** (diagnose freely, act only through
the approval channel: one standing root grant for contrast,
`systemctl restart/reload` and `apt-get update` approval-gated, the
full §9 ceremony documented step by step), and **`webserver/`**
(Apache + fail2ban maintenance: reads, enumerated writes through
`tee`, validate, approval-gated restart). All three were validated
live on a real host before shipping.

## 8. Observability (phase 1 headline)

The phase-1 goal, in the operator's words: *"everything works — but what
else did it do? which files did it create or modify? which other servers
did it touch?"*

### 6.9 Root mode (the explicit opt-out)

A policy may set `mode = "root"` with a mandatory per-exec `timeout`
(1..3600 seconds). Deny rules are the only rules allowed — everything
not denied runs **as root**: the gateway wraps each allowed argv in
`sudo -n` through a wildcard sudoers grant (`sy ALL=(root)
TIMEOUT=<n> NOPASSWD: ALL`) generated at install. argv[0] is still
resolved against the fixed PATH, argv is still ASCII-checked, each
exec still gets its scope, output cap, timeout and pre/post journal
events with `PRIV=1`.

This mode exists for one workflow: **total freedom on a custom,
disposable host, with a record**. It is not control, and the code
refuses to let you believe it is:

- allow, `privileged`, or `approval` rules in root mode are lint
  errors — they are meaningless when everything already runs as root;
- install requires active auditd rules (same gate as permissive: the
  journal is the only thing root mode still offers, so the kernel
  source must be real);
- `doctor` warns about root mode on every run;
- NNP is off (sudo needs setuid) — containment is meaningless for a
  root tree.

The honest limit, stated everywhere the mode is named: **after the
first root exec, the agent can mint access the journal never sees**
(`useradd`, a new authorized key, a changed shell). The record is only
as good as the agent's cooperation. Treat the host as disposable; if
you want rollback, snapshot the VM in your hypervisor first — outside
`sysh`.

### 6.10 Agent scripts (one command per line)

The agent's batch workflow, kept inside the argv policy. A policy may
declare an **agent-script directory**:

```toml
agent_scripts = "/var/lib/sysh/agent-scripts"
```

A script there is a plain text file: first line `#!/usr/bin/sysh`,
then **one command per line**. When argv[0] names a file under that
directory (bare name, relative subpath, or absolute path — symlinks
resolved, traversal out refused), the gateway runs it as data, never
exec's it: it reads the file whole (≤ 64 KB, ≤ 1000 commands), checks
the shebang and the file's ownership, then feeds every line through
the same decision pipeline as a direct exec — same rules, same
denylist, same journal pre/post pair per line.

Properties, by construction:

- **No shell semantics exist inside.** No variables, no pipes, no
  `$(...)`, no expansion — a line is an argv or it is a refusal.
- **The kernel never honors a foreign shebang**: a `#!/bin/bash`
  file in the directory is refused with the same teaching the
  runtime denylist uses. There is no free bash behind the mechanism.
- **Fail closed on the file**: regular file, owned by the gateway
  user or root, no group/world-writable bits, read whole before the
  first line runs (a mid-run rewrite cannot change what executes).
- **Aborts at the offending line**: a policy-denied line stops the
  script (exit 125) — later lines never run. A line whose command
  merely fails (nonzero child exit) does not abort it, like `sh -e`
  is *not* set.
- **Recursion refused**: a script that names itself (directly or in
  a chain) is denied, not looped.
- The directory itself is root-owned and not group/world-writable
  (linter SevError at install, doctor re-verifies live). The agent
  may own files inside — e.g. a sy-owned `drop/` subdirectory for
  uploads — but never the directory or its path.

Two run modes (§6.13): `agent_scripts_mode = "lines"` (default,
everything above) or `"traced"` — real scripts with any shebang,
every execve in the tree argv-checked under a ptrace tracer.

The upload workflow stays agent-driven: the operator acks a
  transfer rule (rsync/scp are warn-class denylist entries,
  acknowledgeable) scoped to the drop subdirectory, and the agent
  syncs scripts there. Nothing about the script runtime changes what
  a transfer may carry: each file still needs the sysh shebang and
  per-line policy to run.

**What this is not**: it is not a shell, and it does not make python
usable. Non-exec actions a real shell would perform (redirections,
`/dev/tcp`, job control) do not exist; interpreters stay denied.
Agents compute where they live and act here per argv — the script is
just a batch of argvs.

### 6.11 The interactive console (`ssh sy@host`)

An interactive login (no command, PTY attached) opens an **argv
REPL** instead of refusing: the gateway prints its own banner — mode,
key id, script directory, the honest limits — then reads one command
per line. Every line goes through the same pipeline as a `-c` exec
(same result lines on stderr, same journal events). `cd` is the only
verb the console interprets itself — navigation state, not an
action, journaled as a builtin; the kernel enforces who may chdir
where, and policy paths are absolute and unaffected. `exit` or EOF
closes the session.

Two configuration points make it exist:

- The sshd drop-in sets `PermitTTY yes` for the sy user: a PTY
  reaches only the gateway — the confinement — where every line is
  policy-checked. An operator who wants the channel `-c`-only sets
  it back to `no` and interactive logins refuse with `no_input`.
- Keys registered for console use carry the four negatives of
  `restrict` minus `no-pty` (`no-X11-forwarding,
  no-agent-forwarding, no-port-forwarding, no-user-rc`);
  `sysh auth add` accepts exactly that set or `restrict`, nothing
  else. `restrict` keys simply never get a PTY.

The banner is the MOTD sysh fully controls (sshd's own MOTD prints
before it on interactive logins; non-interactive `-c` sessions never
see any MOTD, which is why `help` exists as an argv).

### 6.12 Teaching surfaces (deny with an answer)

The linter has always refused rules for shells, interpreters and
execution wrappers (SevError, not acknowledgeable). Since v0.6 the
gateway enforces the same list **at run time, in every mode except
root**: resolving argv[0] (fixed PATH for bare names, symlinks
followed) and refusing with a teaching detail — what the name is,
why it is structural, and what to do instead (one command per exec,
or a sysh script; `'help' explains`). This closes the permissive-mode
hole where `bash` would otherwise have run freely.

The rest of the deny path teaches too — each hint answers an
unbriefed agent's actual first moves (all observed live, see below):

- **Shell operators** (`uptime && whoami`): argv is split on
  whitespace; `&& ; |` are literal words — send one command per exec.
- **Bare names** (`uptime` when the rule says `/usr/bin/uptime`):
  rules name binaries by absolute path; the hint names the path to
  try. (No leak: it is information `sy-policy` already prints.)
- **Transfers** (`scp`, `sftp`, `rsync` with no rule): uploads need a
  policy rule the operator acknowledges (rsync scoped to the
  agent-scripts directory); ask your operator.
- **Script modes** (`rsync -a` preserving a 0664 source): re-upload
  with 0600; the refusal says rsync preserves source permissions.
- **`sysh-result` misuse**: the usage line includes the id format
  (`req_` + 12 hex, from an `approval_required` response).
- `help` accepts and ignores arguments — `help scripts` asked the
  right question; refusing it was the channel being smug. It lists
  the scripts available in the agent-script directory (names only)
  and states how to place one.

**Measured, not asserted.** The teaching surfaces were validated by
handing an unbriefed LLM agent (no sysh documentation, just an ssh
command and a task) the channel and watching the sysh journal:

- v0.6.0-beta1: tasks "uptime/id" solved in 15 s, but the batch
  task never completed — ~40 blind probes for an upload builtin
  over 8 minutes, then the agent gave up on the channel and went
  reading local source instead.
- v0.6.0-beta2 (hints above + the acked rsync transfer rule): the
  same agent completed the batch task end to end — discover `help`,
  list scripts, upload via the acknowledged rsync rule, recover from
  the file-mode refusal by reading it, run — in about 90 seconds,
  with zero blind probes. Its closing line: "The refusals aren't
  obstacles — they're documentation."

### 6.13 Traced agent scripts (real interpreters, still argv-governed)

`agent_scripts_mode = "traced"` turns the agent-script directory
from data into real scripts: **any shebang** — bash, python, node,
whatever the operator allows to be installed — runs as a child of the
gateway while a **ptrace tracer** intercepts every `execve` in the
process tree. The argv is read from the stopped child's memory at
syscall entry, policy-checked by exactly the same `Match` as a
direct exec, and a refusal **fails the syscall itself** (`-EPERM`):
the interpreter sees "Operation not permitted", the journal sees
the full argv pre/post pair, and the script runs on. Nested
interpreters get no free pass: `/bin/bash -c '...'` inside a script
is itself an execve, and it needs its own rule or it is refused.

Properties:

- **Same argv semantics**: rules match the exact argv of every exec
  in the tree. Fixed positions, `rest`, deny rules — identical to a
  direct exec. Builtins, approval, and privileged rules are
  direct-exec concepts and do not apply inside a tree.
- **Pipes and redirections inside a script are interpreter
  plumbing, but their sides are execs**: `uptime | grep x` in a
  bash script gets the pipe built by bash (not argv-visible, the
  honest limit above), while **each side is intercepted and
  policy-checked** — verified live: the allowed side runs, the
  side without a rule fails with "Operation not permitted", bash
  reports exit 126, and the script continues. The pipe as a shape
  is never trusted; the argv on each end is.
- **argv[0] inside a tree is the word the interpreter passes**:
  a script line `grep x` execs `/usr/bin/grep` (the interpreter
  resolves PATH) but the journaled and matched argv is
  `["grep" "x"]`. A traced policy therefore needs **bare-name
  argv[0] rules** (`argv = ["grep"]`, `path = "/usr/bin/grep"`)
  for the commands its scripts use — each one an explicit operator
  decision; meaning stays in the policy's `path`, never in PATH.
- **Refusal is a failed exec, not an abort**: unlike line mode
  (§6.10, which stops at the offending line), a refused exec looks
  to the interpreter like `Permission denied`; whether the script
  continues is the script's own logic. The teaching line still
  reaches the agent in-band on stderr.
- **The interpreter's own exec is exempt by construction**: the
  child `PTRACE_TRACEME`s before the initial exec, so the first stop
  the tracer sees is *after* the shebang interpreter is already
  loaded. The script file itself is checked like line mode (§6.10
  file rules) plus an owner-exec bit and the same 64 KB cap.
- **Containment without a scope**: the tracer must be the tracee's
  ancestor, so a systemd scope is impossible. Instead: rlimits
  (CPU, NPROC=256 mirroring the scope task cap — concurrent traced
  runs share the gateway uid's budget, which is the intended bound
  — 1 GB address space, 64 MB file size), a whole-run timeout
  (600 s default), `PTRACE_O_EXITKILL` (the kernel kills the whole
  tree if the gateway dies), and a private process group for clean
  kills.
- **The kernel suppresses setuid under ptrace** (LSM_UNSAFE_PTRACE):
  a traced exec never gains privileges the tracer could not already
  grant, so nothing in the tree can escalate through a setuid
  binary.
- **Kill switch**: `sudo touch /run/sysh/traced-off` makes every
  traced run refuse instantly until the file is removed (scripts
  still run as line mode if the policy says `lines`).
- **amd64 only** (build-tagged): the tracer reads registers by
  syscall number, so each arch needs its own file. Other builds
  refuse traced mode with a clear message rather than degrading.

**Honest limits, stated in the lint too**:

- Only `execve`/`execveat` are inspected. What the interpreter does
  with builtins, redirections, and file writes is **not**
  argv-visible and runs with the unprivileged gateway user's
  ordinary rights. The operator opts into that by choosing traced
  mode for a directory they curate and writing rules for exactly
  what the script may exec; deny-listing path shapes is the file
  layer's job (fscheck), not argv's.
- The runtime denylist is deliberately **not** re-applied inside a
  traced tree: the denylist exists because a shell runs commands
  "the policy never sees" — under tracing the policy sees every one
  of them, and the linter still refuses to write rules for denylisted
  names, so nothing can match them. In permissive mode every execve
  in the tree is journaled.
- One tracer thread runs the whole tree (ptrace binds the tracer to
  the exact thread that forked; the stdlib `SysProcAttr.Ptrace`
  comment warns about this and the code follows it).

**What this is not**: it is not sandboxing. It is argv enforcement
extended into a process tree the operator chose to allow — the
interpreter can still burn CPU until the timeout, still write files
the `sy` user can write, still read what `sy` can read. Operators
who want the strictest posture keep the default `lines` mode and
lose nothing.

### 8.1 Event model

Every exec attempt — allowed, denied, malformed, locked down — produces one
structured event: timestamp, key id + fingerprint (sshd-derived, §5),
decision + matching rule index, full argv, exit status, duration, systemd
unit name, and the **SHA-256 of the policy file** that made the decision —
so any log reader can tell exactly which policy version authorized each
exec. Phase 2 adds request/approval/result events to the same stream.

### 8.2 Sinks (separated, by who can write them)

- **`sy`-side events → journald** (native API; identifier `sysh`). The
  journal attaches kernel-trusted `_UID`, `_PID`, `_EXE` that the `sy` UID
  cannot forge. **Fail closed:** if the journal write fails, the exec is
  denied. Journal rate limiting and vacuuming can drop messages silently,
  though; `doctor` surfaces the lost-message counters, and off-host
  forwarding (§8.3) is the real detection.
- **Root-side events (phase 2 approvals; phase 1.5 sudo lines) →
  `/var/log/sysh/root.log`**, root:root 0600, **hash-chained** (each entry
  includes the hash of the previous). `sy` has no write handle on it at all.
- No shared writable audit file exists. (The v1 design's single
  append-only log was forgeable by `sy` — it could append fake root-side
  entries; the review caught this, and the split removes the entire class.)

### 8.3 Fleet correlation

`sysh` emits; it does not ship. Forward journals and audit logs with your
existing stack (rsyslog, `systemd-journal-remote`, Wazuh). Cross-host
questions — "which other servers were touched during this incident?" — are
answered by correlating the `sysh` identifier across hosts in that stack.
`sysh audit tail` (root) gives the local view.

### 8.4 auditd integration (kernel-attested; mandatory in permissive mode)

The package installs auditd rules scoped to the `sy` UID (debconf opt-in,
default yes when auditd is present; **`policy install` refuses a
permissive policy when they are not active**, §6.6), keyed `sysh`:
`execve`, write-class syscalls (`open`, `openat`, `creat`, `rename`,
`unlink`, …), and **`connect`** (destination addresses). This answers
"which files did it create or modify, which hosts did it contact" **at
kernel level** — below any forging ability of the UID — landing in
`/var/log/audit/audit.log` for the same forwarding pipeline. Rules are
removed cleanly on purge.

### 8.5 Disclosure

Command output — including phase-2 root command output — flows to the agent
and, for LLM agents, to its model provider. Documented to approval holders;
operators should assume outputs are externally observable.

## 9. Privileged operations

Two mechanisms, one invariant: **root argv are a closed, root-owned list.**

- **Phase 1.5 — operator pre-authorization (shipped).** A `privileged`
  rule plus `policy install` produces an exact-argv
  `sy ALL=(root) TIMEOUT=<n> NOPASSWD: <argv>` grant in
  `/etc/sudoers.d/60-sysh`, `visudo`-validated, regenerated on every
  install, removed when the last privileged rule goes. The gateway execs
  `sudo -n -- <argv>`; events carry `PRIV=true` and sudo's own journal
  line (with the invoking uid) is an independent second record. The
  linter mandates `ack = true` + explicit `timeout`, forbids `rest` and
  whitespace inside argv elements, and refuses permissive+privileged.
  This trades the strict containment of an always-NNP tree for
  observability: every root exec still names the key, argv, rule, and
  outcome.
- **Phase 2 — approve-executes (implemented as described below).** For
  root work the operator did *not* pre-authorize. Rule syntax:
  `privileged = true, approval = true` (patterns and rest allowed — the
  approver re-checks and types them; no standing sudoers grant is
  generated; the gateway stays under NNP). Approving over
  `ssh -t root@server sysh approve req_…` is transport A; signed
  approvals (`sysh approver` + `sysh approve --sig`, item 6 below) are
  transport B; a bot-relayed transport may follow over the same
  primitive.

Design principle for phase 2: **approval chooses *when*; the root-owned
policy chooses *what*.** The agent never executes a privileged argv that
policy did not pre-authorize; there is no bearer token to steal, replay,
or transport.

1. The agent execs an argv matching a `privileged` rule. The gateway writes
   a **request file** into `/run/sysh/requests/` (the `root:sy 1730` (sticky) drop
   box of §4.2; its contents are *untrusted data*): argv, fingerprint,
   key id (claimed label), timestamp, request id. Strict grammar,
   size-capped, ASCII-only, bounded by the request lockout (§9.3). The
   client receives exit 30 + the request id on stderr and should report
   and stop (the MCP contract says the same, §10).
2. A human, interactively on the server:

```console
root@server:~# sysh approvals
req_a1b2c3  argv=["systemctl","restart","nginx"]  key=sysh-agent/server.example  age=12s
root@server:~# sysh approve req_a1b2c3
type the pattern-chosen argument: nginx_
```

   `sysh approve` (root; stdin must be a real TTY — pipes are refused):
   opens the request via the spool's safe pattern (`openat` +
   `O_NOFOLLOW|O_NONBLOCK` — a planted FIFO must not hang the approver —
   then `fstat`: regular file, `st_nlink == 1`, size-capped), parses it
   with a strict grammar, **re-checks the argv against the policy's
   `privileged` rules itself** (an operator cannot approve anything policy
   forbids), and requires the human to **type the pattern-matched
   arguments themselves** — the unit name, the path, whatever the policy's
   patterns chose; that is the only attacker-influenced content in the
   request. A fully literal rule needs only a yes/no. It then **executes
   from the same in-memory copy it displayed**, under a one-shot
   `systemd-run` unit (clean environment, cgroup, `TasksMax`, `MemoryMax`,
   timeout). The result is written root-side (`root:sy 0750`); the agent
   fetches it read-only via `sysh-result req_…` (TTL'd, then removed).
   Raw command output is never streamed to the approver's terminal — it
   is attacker-influenced text; it lives in the result file, and any
   display is escaped.
3. Request hygiene: identical live requests (same argv hash) are deduped;
   more than 5 live pending requests refuse new ones until approved or
   expired (default request TTL 10 min) — the approval-fatigue counter
   (R2). Agent-supplied "reason" text, if ever added, is untrusted display
   data. The request id is deterministic over (argv, key id): `sysh
   approve` and `sysh approvals` recompute it from the parsed body, so a
   file rewritten under a valid-looking name is refused before any human
   or policy sees it (verified: TestApproveTamperedRequest).
4. **Exclusive claim**: `sysh approve` takes the request under an
   `O_EXCL` root-owned marker (`<id>.claimed` in the drop box) before
   prompting; every exit path releases it. Two operators approving the
   same request concurrently cannot both execute — exactly one claim
   exists at any moment (the race was found and closed live: two
   concurrent approves used to double-execute). A marker stranded by a
   crashed approver is stealable once older than the request TTL. The
   drop box is `1730` (sticky): sy may create files but cannot remove or
   rename files it does not own — root's claim markers included.
5. No sudoers line, no setuid helper, no tokens, no replay journal exists
   anywhere in this design. Elevation happens only inside a root process a
   human is watching.

6. **Signed approvals (transport B, shipped).** Approval power is bound
   to a **registered approver key**, not to whoever happens to hold a
   root shell:

   - `sysh approver add <name>` registers a public key under
     `/etc/sysh/approvers/` (root-only; one key line per file; optioned
     keys refused; software keys accepted with a warning, `sk-*`
     hardware-backed keys recommended — with `sk-*`, no signature
     exists without a physical touch on the token).
   - `sysh approve <id> --show` prints the exact request bytes for
     signing; the operator signs them anywhere with stock tooling:
     `ssh-keygen -Y sign -f <key> -n sysh-approve <request-file>`, and
     submits: `cat file.sig | ssh root@server 'sysh approve <id> --sig'`.
   - `--sig` verifies the SSHSIG blob **in-process**
     (`golang.org/x/crypto/ssh`; no ssh-keygen on the verify path —
     `ssh-keygen -Y verify` proved unreliable across distro builds).
     The signature must be over the request's exact bytes, under
     namespace `sysh-approve`, made by a key byte-identical to a
     registered approver's; the approver's registered name lands in the
     audit event. Requests remain TTL'd and single-use: a captured
     signature approves nothing else, and the same argv re-requested
     later is a fresh request (fresh timestamp, fresh bytes) needing a
     fresh signature.

   Residual R1 (operator-laptop malware), precisely stated now: a
   software approver key can be stolen and used to mint signatures
   silently; an `sk-*` key cannot sign without a human touch on the
   hardware token, which is why the registry recommends them. The
   typed-argument challenge of transport A remains available for
   operators without hardware tokens.

**Future candidates (post-0.4, deliberately not shipped):**

- `sy approver-init` — a one-command wizard wrapping `ssh-keygen
  -t ed25519-sk` + `sysh approver add`, so the one-time hardware
  setup stops being manual ceremony.
- A **phone-passkey approval transport** (WebAuthn, hybrid/cross-device
  from the operator's phone — no key material on the laptop). Research
  note from w3c/webauthn#1204: on localhost the browser's origin/rpId
  machinery does not isolate local processes, so the security boundary
  stays exactly where it is today (registered credential + challenge
  bound to the request bytes + the human gesture); WebAuthn would be a
  UX and device-reach win, not a trust win. The argv display residual
  is identical across all transports.


## 10. Laptop side: the `sy` client (`sy mcp`)

A small stdio MCP server for agent harnesses, shipped as a mode of the
`sy` client binary (§1.1) rather than a separate name. It holds only per-host agent
keys (unprivileged by construction) and **never** has approval or listing
power: its tools are `sy_exec`, `sy_docs`, `sy_policy`. An agent needing
elevation surfaces the request id and finishes its turn.

Hard requirements (local code-execution on the operator laptop is the risk
here):

- **Hosts come from a fixed, operator-edited registry file**
  (`~/.config/sy/hosts.toml`: address, user, per-host key) — never from
  agent input. This kills the `-oProxyCommand` argument-injection class.
- SSH is `golang.org/x/crypto/ssh` in-process: user and key come from the
  registry entry only; **host keys are verified strictly against
  `~/.config/sy/known_hosts`** (fail closed; populate via `ssh-keyscan`).
- Agent-supplied argv is validated (printable ASCII, no whitespace/control
  characters — reject rather than let the remote re-split); everything
  else is the server's call — policy decides, the client never does.
- Exit codes and the stderr contract (§6.4) surface as structured results;
  `approval_required` (exit 30) responses carry the request id and
  instruct the agent to report and stop, not poll.

`sy` also carries the **operator-side approval ceremony** — `sy
approvals [host]` (listing passthrough) and `sy approve [host] <id>` —
which wrap transport B into one command: fetch the exact request bytes
from the server over the operator's root SSH channel, display the
server-recorded argv, sign with the configured approver key
(`hosts.toml [approver] key`, typically `sk-*` — PIN and touch happen
inside `ssh-keygen`, in the operator's terminal), and submit. The
command recomputes the request id from the fetched content locally and
refuses on mismatch before anything reaches the signing gesture. Between
the display and the signature sits a confirmation prompt (TTY-only,
refused on pipes): with `sk-*` keys the PIN and touch inside
`ssh-keygen` are the gesture, but a passphrase-less software key signs
silently — for that case the operator typing `yes` after reading the
server-recorded argv is the whole ceremony. When the approver key is
`sk-*` (detected from its paired `.pub`), the ceremony also runs an
insertion loop first — "insert your YubiKey…", polling every 500ms for
up to 30s — because `ssh-keygen` fails outright with no token attached.
Presence is probed with `fido2-token -L` when available (any
authenticator) or the Yubico USB vendor id in sysfs otherwise; on
timeout nothing is signed and the request stays pending. With a
software key the loop is skipped.

Why the ceremony is operator-run and never agent-run: the FIDO2 PIN and
touch prompts are *blind* — they authorize whatever bytes the invoking
process signs. If the agent drove the loop ("insert your YubiKey…",
"enter PIN…") it could display one argv while signing another; the
gesture would then approve the hidden one. The display that accompanies
the gesture must come from the server over a channel the agent cannot
write to — root SSH with the operator's key. `sy approve` is
deliberately absent from the MCP tool list: the agent's role is to
report the request id and wait (polling `sysh-result` is fine).

`sy` runs in a different trust domain from the server package. It rides
in the same .deb (inert on hosts: a client without a hosts.toml does
nothing), but its trust assumptions live on the operator machine. **Deployment requirement DR1:** the agent harness
(and `sy`) runs as a **dedicated OS user on the operator machine**,
holding only agent keys — never the operator's root SSH keys, never
`ControlMaster`, never agent forwarding for root sessions. Without DR1 the
model collapses to "the agent can read your root key"; with it, harness
compromise does not compromise the control channel.

Key generation needs no tool: it is the documented `ssh-keygen` one-liner
of §4.3.

## 11. Threat model

### Adversaries

- **A1 — compromised or misbehaving agent** (the `sy` account, or a holder
  of an agent key). Primary target.
- **A2 — malicious local unprivileged user.** Neutral: the tripwire is
  theirs to pull; nothing else is reachable.
- **A3 — malware on the operator's laptop.** Partially in scope; bounded by
  DR1 (harness user separation) and FIDO2 root keys. See R1.
- **A4 — root compromise of the server.** Out of scope; game over.
- **A5 — network attacker.** Mitigated by SSH; `sysh` adds no channels.

### Properties

- **P1** — the agent executes exactly allow-listed argv (exact length,
  anchored patterns, absolute paths, scrubbed env), or — in permissive
  mode — anything, but only as unprivileged `sy`.
- **P2** — the agent cannot modify its policy, authorized_keys, key map,
  request state, root-side results, or root-side audit; and cannot forge
  an audit record *attributed to the gateway binary* without code
  execution inside the gateway process itself (journald attests
  `_EXE`/`_UID`/`_PID`; consumers filter on `_EXE=/usr/bin/sysh`;
  `DUMPABLE=0` and the ptrace checks raise the bar; auditd is the
  independent kernel-level source).
- **P3** — **no process in the agent tree can gain privileges** (NNP,
  kernel-enforced) — including via any setuid binary or sudoers line
  elsewhere on the host.
- **P4** — the base install has no elevation path at all; phase 2 adds
  elevation only inside a root process a human is interactively driving,
  gated on policy re-check and full-argv confirmation.
- **P5** — every exec attempt is recorded before execution; audit failure
  fails closed.
- **P6** — the MCP surface never grants approval power, never accepts
  hostnames from agents, and runs isolated from root credentials (DR1).
- **P7** — `sysh` weakens nothing on the host: one system user, one scoped
  sshd `Match` block, optional auditd rules; sshd changes are validated
  (`sshd -t`) and rolled back on failure.

### Residual risks (accepted, named)

- **R1 — operator endpoint compromise.** With DR1 + FIDO2 root keys,
  harness-level malware cannot reach the control channel. Remaining:
  malware running *as the operator user* can drive an `ssh -t` approval
  session (a local TTY can be synthesized and fed). Mitigations: typed
  pattern-argument confirmation (§9), request dedup, lockout,
  hash-chained root audit. Signed approvals (§9, transport B, shipped)
  close the signing part: with an `sk-*` approver key, no signature
  exists without a human touch on the token. Remaining: same-user
  malware can still *drive* a ceremony and control the display the
  operator reads — the argv box must come from the server over the
  operator's channel (`sy approve`), and the server-side audit trail
  records every approved argv.
- **R2 — approval fatigue.** Dedup, short request TTL, typed confirmation,
  lockout. Bounded, not eliminated.
- **R3 — policy authoring errors.** The linter (patterns, paths,
  escape-hatch denylist) is v1-mandatory, but a human can still write a
  rule that is technically safe and operationally unwise.
- **R4 — one UID, many agents.** Key identity is attribution, not
  isolation: agent keys share signals, `/proc`, `/tmp`, and the filesystem
  namespace. The consequence: same-UID code (trivially available in
  permissive mode, or after a bug in an allowed tool) can tamper with a
  gateway process where Yama's `ptrace_scope` permits it — mitigated by
  `DUMPABLE=0` (§6.7), the `ptrace_scope` doctor check, and the mandatory
  auditd requirement in permissive mode (§6.6), but not eliminated.
- **R5 — output exfiltration.** Command output flows to the agent and its
  model provider (§8.5). Disclosed, not prevented.
- **R6 — infrastructure trust.** systemd (scopes, journald), auditd, and
  sshd are assumed functional and uncompromised; `sysh` builds on them
  deliberately rather than reimplementing them.

## 12. Rejected or removed (with reasons)

- **Agent-side enforcement** (prompt rules, harness policies): the client
  is the adversary.
- **Management daemon / API plane:** another root-bearing service where
  SSH suffices.
- **chroot / jails / microVMs:** the product is real-host operation with
  least privilege, not isolation.
- **Standing sudo with command allow-lists:** sudoers glob matching is
  string-based and bypassable; elevation must be event-based.
- **Bearer grant tokens, `sysh-exec`, the sudoers line, the replay journal,
  token transport (all v1-design elements):** removed wholesale. The
  sudoers line let the `sy` UID reach the privileged helper *without* the
  gateway, making gateway-side controls (policy, lockdown, audit)
  irrelevant on the elevation path; tokens added replay windows, transport
  exposure, and race-prone journaling. The approve-executes model (§9)
  provides the same human gate with none of that surface.
- **Signatures on policy, host keypair:** removed. With host-local keys
  they defended only against below-root writers, which file ownership and
  permissions (verified at load) already cover; they added a failure mode
  and key-management burden (cloned images sharing keys). Revisit only if
  a multi-admin provenance requirement appears.
- **A second network protocol:** SSH is the protocol; everything else is
  local commands.

## 13. Review disposition (v1 → v2)

v1 was externally reviewed. Disposition of the findings:

| Finding | Resolution |
|---|---|
| `sy` could reach root exec via sudo, bypassing gateway controls | **Redesigned in phase 1.5.** The only sudoers entry for `sy` is the root-owned fragment `policy install` generates — exact argv, `TIMEOUT`, `NOPASSWD` only; no shells, no wildcards, `!setenv`. NNP stays on the whole agent tree whenever the policy has no privileged rules (§6.7); the linter blocks setuid allow-rules otherwise |
| Matcher over-broad (`len >=`, intra-word `*`, `--option=value` injection); deny/first-match contradiction; PATH search; env not scrubbed | **Accepted.** Exact length + anchored patterns that cannot match leading `-` (§6.2); deny-first (§6.2); absolute paths + scrubbed env (§6.2); mandatory linter with escape-hatch denylist (§7) |
| Audit log forgeable by `sy`; "+a" unreliable; "tamper-evident" claim unsupported | **Accepted.** Sinks split: journald (kernel-attested) for `sy`-side, root-only hash-chained file for root-side; fail closed (§8.2) |
| Approval step weak (argv[0] rubber stamp; Unicode display attacks; no dedup) | **Accepted.** Full-argv confirmation code; ASCII-only argv at the gateway (§6.1); dedup by argv hash (§9.3) |
| MCP: host/argv injection → laptop code exec; harness/root-key separation | **Accepted.** Fixed host registry, locked ssh invocation, argv validation, separate distribution, DR1 (§10) |
| authorized_keys 0600 breaks login; token/journal/hashing/spec bugs; ExposeAuthInfo; sshd drop-in gaps; postinst gaps; shared /run dir; policy TOCTOU; exit-code collisions; setsid escape; output exfiltration | **All accepted** and folded into §4–§8 as written above |
| Q1–Q7 | Q1 moot (no tokens); Q2 dedicated tripwire dir (§6.5); Q3 moot (no helper); Q4 journald + root file (§8.2); Q5 root data authoritative, agent fields untrusted (§9); Q6 yes — fingerprint identity + key map (§5); Q7 separate `sysh-mcp` (§10) |

Partial deviations, for the reviewers' attention:

- **Exit codes retained** alongside the structured stderr line (human
  convenience; stderr documented as authoritative — §6.4).
- **Signature removal goes further** than the review's "reconsider"
  (rationale in §12).

### v2 → v3 (second review)

| Finding | Resolution |
|---|---|
| "Cannot forge its audit record" overstated (same-UID ptrace; journal drops) | P2 reworded to binary-attribution (§11); `DUMPABLE=0` + `ptrace_scope` doctor check (§6.7); policy SHA-256 in every event (§8.1); drop counters surfaced (§8.2); auditd mandatory in permissive mode (§6.6) |
| `keys.map` 0600 unreadable by the gateway | 0644 — the mapping is not secret (§4.3) |
| Spool `root:root 0730` not `sy`-writable; FIFO/hardlink planting; §6.5 contradicted §9 | `root:sy 1730` (sticky) drop box in volatile `/run`; safe open pattern (`openat`, `O_NOFOLLOW\|O_NONBLOCK`, `S_ISREG`, `st_nlink == 1`, size caps); §6.5 states the narrow exception (§4.2, §6.5, §9) |
| `/run` is tmpfs — postinst-created dirs vanish | tmpfiles.d; spool deliberately volatile (§4.2) |
| `systemd-run --scope` as `sy` needs the user manager | `--user --scope`, sanitized unit names, doctor verifies PAM/user-manager/delegation, marked fallback (§6.7) |
| Own example violated own linter; proof of no-leading-`-` non-trivial | restricted pattern grammar + first-character set from the RE2 tree (§6.2) |
| `$SSH_USER_AUTH` ownership unverified | implementation note: verify on target OpenSSH, read first, cross-check sshd's Accepted-publickey line (§5) |
| Permissive mode: IMDS, lateral movement, kernel exploits | honest "disposable host" wording; mandatory auditd; opt-in owner-match IMDS block for cloud hosts (§6.6) |
| Persistence outside the gateway (cron/at/user units/linger) | linter denylist + doctor tripwires + scope killed on session drop (§6.6, §6.7, §7) |
| Deny rules exact-length; denylist by `argv[0]` misses aliases | deny prefix semantics; denylist on realpath+basename; `ack = true` warning class for write/net tools (§6.2, §7) |
| Journal reading vs no-supplementary-groups conflict | documented opt-in: `systemd-journal` group only, never `adm`/`docker`/`sudo` (§4.2) |
| 8-hex confirmation is copy-paste | type the pattern-matched arguments; fully literal rules are yes/no; output never streamed raw to the approver (§9) |

Softened deliberately (operator's call — this is a sysadmin's daily-use
tool, not a vault): the IMDS block stays opt-in documentation (the primary
deployment target is on-prem VMs with no metadata service), and off-host
forwarding remains a recommendation rather than a requirement.

## 14. Implementation plan (post-review)

> **Status: phase 1 implemented** (single commit history in this repo;
> unit-tested through the sshd boundary; VM e2e pending). Notable
> implementation deviations from this plan, all deliberate:
> no debconf (auditd rules auto-install when present, journal-group is
> a manual subcommand), gateway accepts any non-root uid (the sy↔shell
> binding is enforced by packaging + doctor, which keeps dev hosts and
> tests honest), `auth add` takes the key from stdin and the key id
> from the key comment.

**Phase 1 — base tier + observability:**

1. `sysh` gateway: shell mode, ASCII argv, hardened matcher, permissive
   mode, lockdown, result contract (stderr line + codes).
2. Containment: NNP, systemd scopes, scrubbed env, rlimits, output caps.
3. Sinks: journald events, fail-closed; `sysh audit tail`.
4. Linter + `policy install` + `auth add` (fingerprint/key map,
   `ExposeAuthInfo` reading).
5. Packaging: deb, transactional postinst (user checks, sshd drop-in with
   `sshd -t` + rollback, purge), auditd opt-in.
6. `sysh doctor`: effective sshd config (`sshd -T -C`), ownership/modes,
   lint, supplementary-group check, auditd rule presence.

**Phase 2 — approve-executes:** request spool, `approvals`/`approve`
(TTY, policy re-check, confirmation code, `systemd-run`), `sysh-result`,
hash-chained root log, dedup/TTL/lockout.

**Before any release:**

- Tests: option injection through every wildcard position; symlink, FIFO,
  and hardlink planting in every `sy`-writable path; terminal-escape argv;
  policy TOCTOU; sshd drop-in rollback on a bad config; NNP under a
  hostile setuid; cgroup-kill on forked children; a same-UID `ptrace`
  attempt against the gateway; behaviour after reboot (tmpfiles.d
  recreating the volatile state); a user manager that is not running
  (fallback path); IMDS reachability from `sy` where the block is
  installed; persistence attempts via `crontab`, `at`, and user units.
- Independent review of the **sshd drop-in, package scripts, and auditd
  rules** — not just the Go code; that is where lockout and privilege
  mistakes live.

### `sy watch` — the operator's live wall (§8 read-side)

Read-only observability riding the existing trust topology, with zero
server-side change: for each host in `hosts.toml`, one persistent
`ssh root@host journalctl -t sysh -o json -f` follow (the same root
channel `sy approve` uses, with reconnect/backoff) plus a periodic
`sysh approvals --json` poll, aggregated in-memory (ring buffer) and
served as a localhost web page — SSE live tail, host/key/decision
filters, and a pending-approvals panel with two buttons per request:
*approve here* (the in-web ceremony) and *run in terminal* (the
launcher), plus copy-paste of the exact `sy approve <host> <id>`.

Threat-model notes:

- **The browser can look and drive the ceremony — on the server's
  terms.** Two actions exist on the HTTP surface, both launcher-shaped:

  *Approve here* (in-web ceremony, `POST /api/ceremony[/confirm]`).
  The invariant of the terminal ceremony is that the process that
  shows the argv signs the bytes; here the watch server is that
  process and the browser is only its renderer, the way gnome-terminal
  is the renderer of `sy approve`. When the modal opens, the server
  fetches the pending snapshot and the exact request bytes fresh (over
  its root SSH — a channel it already holds for journal follow, so
  signing adds no standing power to the process). The modal shows that
  argv and demands the **last argv element typed** before anything
  moves — an attention challenge at least as strong as the terminal's
  typed `yes`. The confirm is one-shot: a wrong typing burns the
  ceremony and restart means reading the argv again. Then the server
  runs `ssh-keygen -Y sign` locally — the **token touch happens inside
  ssh-keygen, unchanged** — and submits over the root channel.
  A PIN-requiring (verify-required) key fails headless with an error
  pointing at the terminal path. Operators who find the typing
  ceremony too heavy may start `sy watch --no-challenge`: the touch
  then becomes the only confirmation. That is a real degradation and
  it is documented as one — against the agent nothing changes (the
  touch is the wall either way), but the forced reading of the argv,
  the anti-phishing layer, is gone; click fatigue is how approval
  ceremonies rot. The default keeps the challenge.

  *Run in terminal* (`POST /api/approve`) spawns a terminal emulator
  running `sy approve <host> <id>` and nothing else.

  Gates common to both: request id (`req_[0-9a-f]{12}`) and host
  registry validated, ids must be in the pending snapshot, spawns and
  ceremonies rate-limited (5/min), Host-header must be a localhost
  form. The in-web ceremony additionally enforces **same-origin**:
  `Sec-Fetch-Site: same-origin` (browser-guaranteed since 2020) plus a
  strict JSON content type, so a visited web page cannot drive a
  ceremony — cross-site forms and fetches die at 403/415. Against
  same-user malware the equivalence with the terminal path is exact:
  it can talk to loopback directly, but it can equally drive
  `sy approve` through a synthetic TTY; in both shapes the token touch
  is the wall, and the journal records what was actually signed. What
  the ceremony deliberately preserves is the anti-phishing shape:
  display == signer (no HTTP hop between what you read and what is
  signed), and an argument you must type forces reading it — click
  fatigue is how approval ceremonies rot.
- **Loopback-only by default** (`--listen 127.0.0.1:7321`, non-loopback
  values refused). argv can carry sensitive material; it does not
  belong on a network listener.
- **DNS-rebinding defense:** the Host header must be a localhost form
  (localhost / 127.0.0.1 / ::1, with or without port), or the request
  is refused — the classic attack against local web tools is a visited
  page rebinding a hostname to 127.0.0.1 and reading the dashboard.
- The journal remains the only source of truth; `sy watch` is a view.
  Multiple viewers are independent followers; `journalctl -f` is
  read-only and cheap.
- Cosmetic, deliberate: light "paper" theme by default, terminal-dark
  theme one click away, persisted in localStorage.
