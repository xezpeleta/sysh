# sysh — Project Specification

Status: **design v2, pre-implementation.** This revision incorporates an
external security review of v1 (disposition in §13). No prior prototypes are
assumed; the document is self-contained.

---

## 1. Purpose and scope

`sysh` lets an operator delegate server work to an automated agent (a script,
an LLM-driven CLI, an MCP client) over normal SSH — with a trustworthy record
of everything the agent did.

The problem: operators increasingly let agents operate real servers, and the
options are all-or-nothing. A root key is unacceptable; a normal user is
unaudited in any agent-specific way; and even when an agent *is* given broad
power (snapshot-protected experimentation is a legitimate workflow), the
operator's first question afterwards — *"it works, but what else did it do?
which files did it change? which other hosts did it touch?"* — has no answer.

`sysh` makes the agent's login itself the control point. The agent's account
is an unprivileged system user whose login shell:

- **records everything** — every exec attempt, allowed or denied, with the
  full argv, the invoking key, the decision, and the outcome, to
  kernel-attested sinks the agent cannot forge;
- **can delimit** — enforce a strict allow-list of exact commands (argv
  matching, no shell semantics, fixed absolute paths, scrubbed environment);
- **never elevates** — no process in the agent's tree can gain privileges
  (`PR_SET_NO_NEW_PRIVS`, kernel-enforced). When a command genuinely needs
  root, a *human* approves it on the server, and the human's tool — not the
  agent — executes it (§9, phase 2).

Phase 1 delivers the record and the delimiting. Elevation-through-approval is
phase 2, sequenced deliberately so the harder security surface ships only
after the base is reviewed in production.

## 2. Non-goals

- **Not a sandbox.** The agent runs real commands on the real host as a real
  unprivileged user. No chroot, namespaces, or microVMs.
- **Not root-without-approval.** Shops that want an unrestricted root agent
  are out of scope. The closest `sysh` offers is *permissive mode* (§6.6):
  unlimited as the unprivileged `sy` user, fully recorded, rollback via your
  existing snapshots — never root.
- **Not monitoring or a SIEM.** `sysh` emits structured, attributable events
  (journal, auditd); shipping and correlating them is your existing stack's
  job.
- **Not an agent framework.** No prompting, no planning. Any SSH client works.
- **Does not manage human access.** Operator SSH untouched; `sysh` adds one
  system user, one `Match` block scoped to that user, and nothing else by
  default.
- **Does not defend against root compromise** of the server, by definition.

## 3. Architecture

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
│                            child runs as unprivileged sy, NNP-bit set │
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
│  /var/spool/sysh/requests/ (sy-writable; untrusted data; phase 2)     │
│  /run/sysh/  (root-owned): results, request state                     │
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
2. Create `/etc/sysh/` (root:root 0755), `/run/sysh/` (root:root 0755),
   `/var/spool/sysh/requests/` (root:root 0730, `sy`-writable),
   `/run/sysh-tripwire/` (1777, sticky).
3. Install the sshd drop-in (§5.3). Validate with `sshd -t` before reload;
   **roll back on failure** — a bad drop-in must never lock out admins (P7).
4. debconf: enable auditd integration? (default yes if auditd present)
   → install UID-scoped rules (§8.4).
5. `purge` removes the user, `/etc/sysh`, the sshd drop-in, the auditd
   rules, and the spool. Audit history in the journal is intentionally kept.

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
`fingerprint → key-id` into `/etc/sysh/keys.map` (root:root 0600).

## 5. Identity and keys

- **Agent keys**: ordinary per-host Ed25519 keys on the operator side
  (`~/.config/sysh/keys/<host>`); the host never sees private material.
  Revocation = remove the line from `authorized_keys`.
- **Key identity at exec time**: the sshd `Match` block sets
  `ExposeAuthInfo yes`; sshd writes the accepted-key details to a
  per-session file (`$SSH_USER_AUTH`) which the shell reads to obtain the
  **fingerprint**. The displayed key ID comes from the root-owned
  `keys.map`. Identity in audit events is therefore kernel/sshd-derived,
  not agent-claimed.
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

Per rule, each position is either a literal or a **pattern**: an implicitly
anchored regex (full match) that the linter rejects unless it can never
match a string starting with `-` (no option injection). Examples:
`"nginx|unifi"`, `"[a-z0-9@._\\-]+"`.

- **Exact length by default**: extra arguments are denied. Opt-in
  `rest = "<pattern>"` allows additional positions, each matching that
  anchored pattern.
- **All deny rules are evaluated first**; any match refuses. Then the first
  allow match wins.
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
- `sysh-result <req>` — (phase 2) fetch the outcome of an approved request.

### 6.4 Result reporting

Every terminal outcome writes **one structured line to stderr** (JSON:
class, detail, request id where applicable, key id). This is the
authoritative machine-readable contract. The process exit code is kept as
human convenience only: child exit statuses pass through when a child ran;
gateway refusals use a documented set (2 lockdown, 3 malformed argv, 30
approval required, 125 denied, 126 privileged unavailable pre-phase-2) —
with the explicit caveat that these collide with child codes (`systemctl
status` returns 3; `timeout` uses 124), which is exactly why automation
must read the stderr line.

### 6.5 Lockdown

Any local user may create `/run/sysh-tripwire/lockdown` (a tripwire: an
agent that notices compromise can lock its own channel). While present, all
agent-channel exec is refused (exit 2). Only root clears it, by fixed name.
Root code never opens or follows paths inside any `sy`-writable directory.

### 6.6 Permissive mode

A policy may set `mode = "permissive"`: every well-formed argv (still
ASCII-checked, still NNP, still scoped and journaled) runs as the
unprivileged `sy` user; the OS's own permissions are the only limit. This
serves the snapshot-protected "give it room, keep the record" workflow. It
never grants root; `privileged` rules in permissive mode behave as in §9.

### 6.7 Process containment

Every child exec:

- runs under `PR_SET_NO_NEW_PRIVS` (set before any thread spawns, or via
  re-exec — the flag is per-thread in Linux). Setuid and sudo become
  unusable for the entire agent tree, on both tiers, regardless of host
  configuration. "No elevation surface" is a kernel property, not a claim
  about config files.
- runs inside a transient systemd scope
  (`systemd-run --scope --unit sysh-<keyid>-<seq>`), giving journal
  attribution, `TasksMax`, `MemoryMax`, and kill-the-whole-cgroup on
  timeout (a `setsid`/double-fork cannot escape a cgroup, unlike a process
  group).
- has output capped; on timeout the scope is killed (exit 124).

Multiple agent keys share one UID: key identity is **attribution, not
isolation** (R4).

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
privileged = true             # phase 2: never executed by the agent (§9)
```

- `sysh policy install` (root) **runs the linter and refuses on any
  finding**; `sysh doctor` re-lints installed policies.
- The linter (v1, mandatory): pattern safety (anchored, cannot match a
  leading `-`, cannot match empty), path checks (§6.2), and a
  package-maintained **escape-hatch denylist** — shells and interpreters
  (`sh`, `bash`, `python*`, `perl`, `ruby`, `node`, `awk`, …), argv
  passthrough / execution wrappers (`env`, `nohup`, `setsid`, `stdbuf`,
  `timeout`, `nice`, `xargs`, `find`, `tar`, `git`, `systemd-run`), remote
  and privileged tools (`ssh`, `scp`, `sftp`, `nc`, `socat`, `docker`,
  `podman`, `sudo`, `su`, `mount`), and pagers/editors (`less`, `vi*`, …).
  Over-broad rules are the most likely real-world failure; the linter is
  the countermeasure, not an afterthought.
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
unit name. Phase 2 adds request/approval/result events to the same stream.

### 8.2 Sinks (separated, by who can write them)

- **`sy`-side events → journald** (native API; identifier `sysh`). The
  journal attaches kernel-trusted `_UID`, `_PID`, `_EXE` that the `sy` UID
  cannot forge. **Fail closed:** if the journal write fails, the exec is
  denied.
- **Root-side events (phase 2: approvals, root executions) →
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

### 8.4 auditd integration (opt-in, kernel-attested)

The package can install auditd rules scoped to the `sy` UID, keyed `sysh`:
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

## 9. Privileged operations (phase 2 — approve-executes)

Design principle: **approval chooses *when*; the root-owned policy chooses
*what*.** The agent never executes a privileged argv; there is no bearer
token to steal, replay, or transport.

1. The agent execs an argv matching a `privileged` rule. The gateway writes
   a **request file** into `/var/spool/sysh/requests/` (a `sy`-writable
   directory whose contents are *untrusted data*): argv, fingerprint,
   key id (claimed label), timestamp, request id. Strict grammar,
   size-capped, ASCII-only. The client receives exit 30 + the request id on
   stderr and should report and stop (the MCP contract says the same, §10).
2. A human, interactively on the server:

```console
root@server:~# sysh approvals
req_a1b2c3  argv=["systemctl","restart","nginx"]  key=sysh-agent/server.example  age=12s
root@server:~# sysh approve req_a1b2c3
confirm (8 chars): 3f9a2c1e_
```

   `sysh approve` (root; stdin must be a real TTY — pipes are refused):
   opens the request with `O_NOFOLLOW`, size-limits and parses it with a
   strict grammar, **re-checks the argv against the policy's `privileged`
   rules itself** (an operator cannot approve anything policy forbids),
   displays the full argv and absolute path plus a short confirmation code
   (first 8 hex of the NUL-delimited argv hash — binding the confirmation
   to the *whole* argv), requires that code to be typed, then **executes
   from the same in-memory copy it displayed**, under a one-shot
   `systemd-run` unit (clean environment, cgroup, `TasksMax`, `MemoryMax`,
   timeout). The result is written root-side; the agent fetches it
   read-only via `sysh-result req_…` (TTL'd, then removed).
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

## 10. Laptop side: `sysh-mcp` (separate distribution)

A small stdio MCP server for agent harnesses. It holds only per-host agent
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

`sysh-mcp` runs in a different trust domain from the server package and is
distributed separately. **Deployment requirement DR1:** the agent harness
(and `sysh-mcp`) runs as a **dedicated OS user on the operator machine**,
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
  its own audit record (journald kernel attestation).
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
  full-argv confirmation code, request dedup, lockout, hash-chained root
  audit. Full closure = FIDO2-signed approvals (§9, future).
- **R2 — approval fatigue.** Dedup, short request TTL, typed confirmation,
  lockout. Bounded, not eliminated.
- **R3 — policy authoring errors.** The linter (patterns, paths,
  escape-hatch denylist) is v1-mandatory, but a human can still write a
  rule that is technically safe and operationally unwise.
- **R4 — one UID, many agents.** Key identity is attribution, not
  isolation: agent keys share signals, `/proc`, `/tmp`, and the filesystem
  namespace.
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
| `sy` could reach `sysh-exec` directly via sudo, bypassing all gateway controls | **Accepted, redesign.** Approve-executes model (§9); NNP on the whole agent tree (§6.7); sysh-exec/sudoers/tokens deleted (§12) |
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

## 14. Implementation plan (post-review)

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

- Tests: option injection through every wildcard position; symlink and
  race attempts in every `sy`-writable path; terminal-escape argv; policy
  TOCTOU; sshd drop-in rollback on a bad config; NNP under a hostile
  setuid; cgroup-kill on forked children.
- Independent review of the **sshd drop-in, package scripts, and auditd
  rules** — not just the Go code; that is where lockout and privilege
  mistakes live.
