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
- **Not unrestricted root.** Shops that want an anything-goes root agent
  are out of scope. `sysh` root power is always a closed list of exact argv
  the operator wrote into a `privileged` rule — never a shell, never
  `rest`, never a pattern. For unstructured room the closest is
  *permissive mode* (§6.6): unlimited as the unprivileged `sy` user, fully
  recorded, on a host you treat as disposable — still not root. (Rollback,
  if you want it, is your own hypervisor/backup practice; `sysh` has no
  snapshot integration.)
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
│  /run/sysh/requests/ (root:sy 0730 drop box; untrusted; phase 2)     │
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
   `/run/sysh/requests/` (root:sy 0730 — a **drop box**: `sy` may create
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
(`ssh.ParseAuthorizedKey`), **requires `restrict`**, rejects embedded
newlines and any option granting command/pty/forwarding/agent access,
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
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserRC no
ExposeAuthInfo yes
```

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
`"nginx|unifi"`, `"[a-z0-9@._][a-z0-9@._\\-]*"` (leading class without
`-`).

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
argv = ["systemctl", "restart", "nginx|unifi"]
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
  `ack = true` on the rule before `policy install` proceeds. Over-broad
  rules are the most likely real-world failure; the linter is the
  countermeasure, not an afterthought.
- Loading: open once, `fstat` ownership/mode of file and ancestors, parse
  **that same buffer** (no re-open TOCTOU). Fail closed (all exec denied,
  stderr line explains) on any anomaly.
- The `sy` UID cannot write `/etc/sysh`; no signature scheme is used — §12
  explains why it was removed.

## 8. Observability (phase 1 headline)

The phase-1 goal, in the operator's words: *"everything works — but what
else did it do? which files did it create or modify? which other servers
did it touch?"*

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
  `ssh -t root@server sysh approve req_…` is transport A; FIDO2-signed
  and bot-relayed approvals are future transports over the same
  primitive.

Design principle for phase 2: **approval chooses *when*; the root-owned
policy chooses *what*.** The agent never executes a privileged argv that
policy did not pre-authorize; there is no bearer token to steal, replay,
or transport.

1. The agent execs an argv matching a `privileged` rule. The gateway writes
   a **request file** into `/run/sysh/requests/` (the `root:sy 0730` drop
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
   data.
4. No sudoers line, no setuid helper, no tokens, no replay journal exists
   anywhere in this design. Elevation happens only inside a root process a
   human is watching.

Future (not v1): FIDO2 touch-gated approval via stock
`ssh-keygen -Y sign/verify` over the request hash — closing the
operator-laptop-malware residual (R1) without custom crypto.

## 10. Laptop side: the `sy` client (`sy mcp`)

A small stdio MCP server for agent harnesses, shipped as a mode of the
`sy` client binary (§1.1) rather than a separate name. It holds only per-host agent
keys (unprivileged by construction) and **never** has approval or listing
power: its tools are `sy_exec`, `sy_docs`, `sy_policy`. An agent needing
elevation surfaces the request id and finishes its turn.

Hard requirements (local code-execution on the operator laptop is the risk
here):

- **Hosts come from a fixed, operator-edited registry file** — never from
  agent input. This kills the `-oProxyCommand` argument-injection class.
- ssh is invoked as `ssh -F <controlled config> -- sy@<host> -- <argv…>`
  with `IdentitiesOnly`, `BatchMode`, `ClearAllForwardings`,
  `PermitLocalCommand=no`; `sy@` is hardcoded; `--` is always used.
- Agent-supplied argv is validated (printable ASCII, no whitespace/control
  characters — reject rather than let ssh re-split).
- Exit codes and the stderr contract (§6.4) surface as structured results;
  `approval_required` responses instruct the agent to report and stop, not
  poll.

`sy` runs in a different trust domain from the server package and is
distributed separately. **Deployment requirement DR1:** the agent harness
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
  hash-chained root audit. Full closure = FIDO2-signed approvals (§9,
  future).
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
| Spool `root:root 0730` not `sy`-writable; FIFO/hardlink planting; §6.5 contradicted §9 | `root:sy 0730` drop box in volatile `/run`; safe open pattern (`openat`, `O_NOFOLLOW\|O_NONBLOCK`, `S_ISREG`, `st_nlink == 1`, size caps); §6.5 states the narrow exception (§4.2, §6.5, §9) |
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
