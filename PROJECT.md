# sysh — Project Specification

Status: **design, pre-implementation**. This document is the review target.
It is self-contained; no prior prototypes are assumed.

---

## 1. Purpose and scope

`sysh` is a login shell and companion verifier that lets an automated agent
(a script, an LLM-driven CLI, an MCP client) operate a real server over
normal SSH with least privilege and full accountability.

The problem it solves: operators want to delegate *specific* operational tasks
to agents, but SSH grants all-or-nothing access. Giving an agent a root key is
unacceptable; giving it a normal user is often useless and always unaudited in
any agent-specific way.

`sysh` makes the agent's login itself the control point:

- the agent's account is an unprivileged system user,
- whose shell allow-lists exact commands (argv matching, no shell semantics),
- whose every action is appended to a tamper-evident audit log,
- and whose rare privileged needs are satisfied only by a human-approved,
  single-use, argv-bound, short-lived grant token verified by a root-side
  helper.

## 2. Non-goals

- **Not a sandbox.** The agent runs real commands on the real host as a real
  unprivileged user. No chroot, no namespaces, no microVMs. If you need
  isolation, run `sysh` inside whatever isolation you already have.
- **Not a monitoring/SIEM system.** It audits its own channel only.
- **Not an agent framework or harness.** No prompting, no planning, no tool
  orchestration beyond what SSH argv already provides.
- **Does not manage human access.** Operator SSH is untouched; `sysh` never
  modifies other users, other keys, or default sshd behavior beyond a
  `Match` block scoped to the agent user.
- **Does not defend against root compromise** of the server, by definition.
- **Is not a policy authoring UI.** Policies are files; author them with
  whatever you use today (editor, git, code review).

## 3. Architecture

Two components, both on the server. One optional helper on the operator side.

```
┌────────────────────────────── server ──────────────────────────────┐
│                                                                    │
│  sshd ── exec ──> /usr/bin/sysh            (login shell, uid=sy)   │
│                     │  policy check (signed, root-owned)           │
│                     │  audit append (uid-stamped)                  │
│                     │                                              │
│                     │ privileged argv + valid token?               │
│                     ▼                                              │
│           sudo /usr/lib/sysh/sysh-exec     (root, ONE sudoers line)│
│                     │  verify token: host-key signature,           │
│                     │  argv-hash binding, TTL, replay journal      │
│                     ▼                                              │
│               exec argv as root + corroborating audit entry        │
│                                                                    │
│  /etc/sysh/  (root-owned): policy.toml+sig, host keypair,          │
│              authorized_keys, docs/                                │
│  /run/sysh/  (root-owned): approvals/, token journal, lockdown     │
│  /var/log/sysh/audit.log   (append-only)                           │
└────────────────────────────────────────────────────────────────────┘
        ▲                                    ▲
        │ ssh, per-host agent key            │ ssh, operator's own key
        │ (agent channel, untrusted)         │ (control channel, root)
   any SSH client                        human operator
```

Trust boundaries:

- **Agent channel** (`sy@`): fully untrusted. Everything it touches is
  enforced or verified host-side.
- **Control channel** (`root@`): the operator's own SSH, out of `sysh`'s
  scope. All control operations (`sysh auth`, `sysh policy install`,
  `sysh approvals`, `sysh approve`) are local commands invoked over it.
- **The `sy` UID cannot escalate, cannot rewrite its policy, its keys, its
  audit trail, or its pending approval records.** This is the load-bearing
  property; every design decision below serves it.

## 4. Deployment

### 4.1 Package

A single deb package `sysh` ships:

- `/usr/bin/sysh` — login shell and control subcommands (static Go binary)
- `/usr/lib/sysh/sysh-exec` — privileged verifier (static Go binary)

There is intentionally no daemon, no socket, no service. The only running
code is whatever an SSH session invokes.

### 4.2 postinst (all host-local setup)

The package `postinst` performs, transactionally and idempotently:

1. Create system user `sy` (home `/var/lib/sysh`, owned root, non-writable
   by `sy`; shell `/usr/bin/sysh`).
2. Generate the **host keypair** `/etc/sysh/host.ed25519` (root:root 0600)
   and `host.ed25519.pub` — the signing key for policies and grant tokens.
3. Create `/etc/sysh/`, `/run/sysh/`, `/var/log/sysh/audit.log`
   (append-only attribute where the filesystem supports it).
4. Install an sshd drop-in `Match` block scoped to user `sy`:
   `AuthorizedKeysFile /etc/sysh/authorized_keys` (root-owned 0600 — the
   agent user cannot add keys to itself), plus
   `DisableForwarding yes`, `PermitTTY no`, `X11Forwarding no`.
5. **Privileged tier (debconf question, default *no*):** if enabled, install
   the single sudoers line
   `sy ALL=(root) NOPASSWD: /usr/lib/sysh/sysh-exec`.
   If not enabled, no sudoers entry, and `sysh-exec` is inert: the base
   install has **zero root-elevation surface**.

Rollback on failure removes only what this run created.

### 4.3 Operator onboarding (over plain SSH, no orchestrator)

```console
$ sy keygen server.example        # or plain ssh-keygen; prints:
  restrict ssh-ed25519 AAAA… sysh-agent/server.example
$ ssh root@server.example 'sysh auth add' <<< '<that line>'
$ ssh root@server.example 'sysh policy install' < server.example.toml
```

`sysh auth add` (run as root) validates the line's options (rejects anything
that grants a command, pty, forwarding, or agent access) and appends it to
`/etc/sysh/authorized_keys`. `sysh policy install` (run as root) reads a
policy on stdin, validates it, signs it with the host key, and installs it
atomically (`policy.toml` + `policy.sig`, root-owned).

The per-host agent key lives on the operator side at
`~/.config/sysh/keys/<host>`; the host never sees it.

### 4.4 Two tiers

| | Base | Privileged |
|---|---|---|
| sudoers lines | none | one (`sysh-exec` only) |
| Elevated exec possible | no — policy `privileged = true` rules refuse with exit 126 | yes, token-gated |
| Approval machinery | absent | present |

Enforcement is layered: a privileged rule on a base-tier host is refused at
exec time regardless of what any client claims. Upgrading to the privileged
tier later is additive (install the sudoers line); nothing else changes.

## 5. Identity and keys

- **Host keypair** (Ed25519, per server, root-only): signs policies at
  install and mints/verifies grant tokens. Compromise of it requires root,
  which is outside the threat model by definition.
- **Agent keys** (Ed25519, per host, operator-side): ordinary SSH keys.
  Agent identity in audit entries is the key's comment (e.g.
  `sysh-agent/server.example`). Multiple keys = multiple agents; revocation
  is removing the line from `/etc/sysh/authorized_keys`.
- **Operator root access**: the operator's own SSH keys. **Recommended:
  FIDO2 hardware-backed keys (`ed25519-sk`)** for the control channel. This
  is the only hardware recommendation in the system, and it uses stock
  OpenSSH — no custom cryptography.
- Server host-key verification on the operator side is standard
  `known_hosts` semantics. `sysh` adds nothing and replaces nothing there.

## 6. Gateway semantics (`sysh` as login shell)

### 6.1 argv is the unit of trust

sshd execs the login shell as `sysh -c '<command string>'` for a non-interactive
SSH command. `sysh`:

- splits the command string on whitespace (IFS), performing **no** shell
  expansions, no globbing, no quoting interpretation, no metacharacter
  semantics. `a; b`, `a | b`, `$(x)`, backticks are literal words that will
  not match any sane policy and are denied.
- treats the resulting argv as the request. Matching is positional,
  length-aware (`len(argv) >= len(match)`), with `*` as an intra-word glob
  and `|` as alternatives inside a position.

There is no shell behind the gateway. Compound operational needs are met by
allow-listing a specific command with fixed arguments (or a curated script
installed by the operator for exactly that purpose), never by granting a
shell.

### 6.2 Builtins (pseudo-commands, always allowed)

- `sy-docs` — dump `/etc/sysh/docs/*.md` (operator-maintained host
  knowledge base; how the agent learns *what* to run).
- `sy-policy` — dump the effective policy (minus signatures) so agents can
  self-check before attempting.

Both are read-only and exist because discoverability is the difference
between an agent that asks and an agent that guesses.

### 6.3 Token relay

A grant token is presented as a pseudo-command:

```
sysh-token gt_… -- <real argv…>
```

The gateway strips the wrapper, checks the real argv against policy, and
only then hands the token + argv to the privileged tier. (Open question Q1
lists alternatives considered.)

### 6.4 Exit codes (contract for automation)

| code | meaning |
|---|---|
| 0 | success |
| 2 | lockdown active |
| 3 | malformed request (empty/oversized argv, bad token syntax) |
| 30 | approval required (privileged argv, no valid token); request id on stderr |
| 77 | token rejected (invalid signature, expired, argv mismatch, or replayed) |
| 124 | exec timeout (per-policy, default 60s) |
| 125 | policy denied |
| 126 | privileged tier unavailable on this host |

Codes ≥ 100 pass through the child's own exit status.

### 6.5 Lockdown

Any client may create `/run/sysh/lockdown` (a tripwire: e.g. an agent that
notices compromise can lock its own channel; so can any local user). While
present, all agent-channel exec is refused (exit 2). Only root may remove it.
Pending approvals are not cleared by lockdown; root decides each one.

## 7. Policy model

TOML, human-authored, host-signed at install:

```toml
version = 1
host = "server.example"

[[rule]]
match = ["uptime"]

[[rule]]
match = ["systemctl", "status|show", "*"]

[[rule]]
match = ["journalctl", "-u", "*"]
timeout = 10

[[rule]]
match = ["systemctl", "restart", "nginx|unifi"]
privileged = true
```

- Rules are evaluated in order; first match wins. An explicit
  `deny = true` rule outranks any earlier match.
- `privileged = true` marks rules whose argv may run as root **only** with a
  valid grant token (§8); on a base-tier host such rules exit 126.
- `timeout` bounds the child; on expiry the process group is killed and the
  exit is 124.
- The file is signed by the host key at install; the signature covers the
  canonical byte content. The gateway verifies on every load and refuses to
  serve policy (fail-closed, exit 125 for all exec) if verification fails.
- File and signature are root-owned 0644/0600 in `/etc/sysh/`; the `sy` UID
  cannot write them.

**Rationale for host-local signing:** the signature's job is tamper-evidence
below root (a compromised agent must not be able to rewrite its own policy).
Fleet-wide provenance is a non-goal; operators push policy over their root
channel, and root is trusted on its own host by definition.

## 8. Privileged tier

### 8.1 The sudoers surface

Exactly one line:

```
sy ALL=(root) NOPASSWD: /usr/lib/sysh/sysh-exec
```

`sysh-exec` is a small static binary whose argv handling is minimal by
construction. It performs no shell interpretation, no path resolution beyond
its fixed allow-list, and only two verb modes (request-record, verified-exec).
It is the only root code reachable from the agent channel, and it is intended
to be small enough to fully review. (Setuid was rejected: sudoers keeps the
decision visible in standard host configuration and auditable by standard
tooling.)

### 8.2 Grant tokens

Format: `gt_<base64url(payload)>_<base64url(sig)>`, Ed25519-signed with the
host key. Payload:

```json
{
  "v": 1,
  "host": "server.example",
  "req": "req_a1b2c3",
  "argv_sha256": "…",
  "approver": "root",
  "exp": 1234567890
}
```

Properties, each independently enforced at exec time:

- **single use** — the token's SHA-256 is appended to an append-only journal
  (`/run/sysh/tokens.journal`) at first use; a second presentation exits 77;
- **argv-bound** — `argv_sha256` must equal the hash of the argv actually
  presented, else 77;
- **host-bound** — `host` must match, else 77;
- **short-lived** — `exp` is at mint time + TTL (default 120s);
- **human-minted** — only `sysh approve` (root, interactive TTY) creates
  them (§8.3).

### 8.3 Approval flow

1. The agent execs a `privileged` rule without a token. The gateway asks
   `sysh-exec` to **record a pending request** — root writes
   `/run/sysh/approvals/req_….json` containing the argv, its hash, the
   requesting key id, and a timestamp — and the client gets exit 30 with the
   request id. The gateway itself cannot write this record; it is
   **tamper-proof against the `sy` UID by construction**. This defeats the
   masquerade attack (agent shows the human one argv, then runs another):
   the approver always reads the host-recorded argv, and the minted token is
   bound to *that* argv's hash.
2. A human lists and approves on the server, interactively:

```console
root@server:~# sysh approvals
req_a1b2c3  argv=["systemctl","restart","nginx"]  key=sysh-agent/server.example  age=12s
root@server:~# sysh approve req_a1b2c3
argv[0] to confirm: systemctl_         # must be typed; stdin must be a real TTY
token: gt_…                             # hand to the agent out-of-band
```

3. `sysh approve` requires: run as root, stdin is a TTY (pipe-fed
   confirmation is refused), the typed string equals the recorded argv[0],
   the request exists and is fresh. It then mints the token and **marks the
   request consumed**.
4. The agent retries via `sysh-token gt_… -- argv…`; verification per §8.2;
   success runs the argv as root and appends a corroborating root-side audit
   entry (uid=0, token id, approver, request id).

**Abuse lockout:** more than 5 live pending requests from one host-key
refuses new privileged requests until they are approved or expire
(default TTL for requests: 10 min). Approval fatigue is the known social
residual; the lockout and the typed confirmation are the counters.

## 9. Audit

`/var/log/sysh/audit.log`, append-only (filesystem `+a` attribute where
supported; rotation and archival are the operator's log stack, out of scope).

Each line is JSON with: timestamp, event class (`allowed`, `denied`,
`approval_required`, `approval_granted`, `token_used`, `token_rejected`,
`lockdown`), the full argv, the invoking key id, the exit code, and — for
privileged executions — a second corroborating line written by `sysh-exec`
as root (uid 0, request id, approver). The two-line pair is the evidence
that a human actually gated the elevation.

The `sy` UID can append (it must, to log its own channel) but cannot
truncate, rewrite, or rotate the file. Appendix-level caveat: `+a` is
ext4/xfs-specific; on filesystems without it, the mitigation is
permissions + accepting that a compromised agent can spam but not erase
(Q4).

## 10. Operator-side helper: `sy`

A tiny optional tool for the operator's laptop. Everything it does is
otherwise expressible as plain SSH; it exists only for the pieces that are
not:

- `sy keygen <host>` — create `~/.config/sysh/keys/<host>` (Ed25519) and
  print the exact `restrict …` authorized_keys line. (Plain `ssh-keygen` +
  a documented line would also work; this only removes a copy-paste hazard.)
- `sy mcp` — a stdio MCP server exposing three tools to agent harnesses:
  `sy_exec` (run argv on a host via `ssh -i <key> sy@host`, mapping exit
  codes to structured results), `sy_docs`, `sy_policy`. It shells out to the
  system `ssh` — it holds no credentials of its own beyond the per-host
  agent keys, which are unprivileged by construction.
  **The MCP surface deliberately has no approval capability**: it cannot
  list, mint, or relay tokens. An agent that needs elevation must surface
  the request id and stop.

The control operations (`auth add`, `policy install`, `approvals`,
`approve`, `audit`, `doctor`) are **not** wrapped. They are plain SSH
commands, and keeping them that way is a design decision: the operator
should see and feel root when using root.

`sysh doctor` (root, on the server) checks installation conformance: tiers,
key/file ownership and modes, policy signature validity, sshd block
presence, audit writability.

## 11. Threat model

### Adversaries

- **A1 — compromised or misbehaving agent** (the `sy` account, or a client
  in possession of an agent key). *Primary target.*
- **A2 — a malicious local unprivileged user** on the server. `sysh` should
  be neutral to them: the lockdown tripwire is theirs to pull, nothing else
  is.
- **A3 — malware on the operator's laptop.** Partially in scope; see R1.
- **A4 — root compromise of the server.** Out of scope; game over by
  definition.
- **A5 — network attacker** between clients and server. Mitigated by SSH
  itself; `sysh` adds no channels.

### Properties

- **P1** — An agent can execute exactly the allow-listed argv, nothing else.
  No shell, no expansion, no compound syntax (§6.1).
- **P2** — An agent cannot modify: its policy, its authorized_keys, its
  pending approval records, its audit history, the host keypair (§3, §7, §8.3).
- **P3** — Privileged execution requires a token that is single-use,
  argv-bound, host-bound, ≤120s old, and minted by an interactive root
  confirmation (§8).
- **P4** — The base tier has zero root-elevation surface: no sudoers, no
  setuid, no daemon (§4.4).
- **P5** — Every exec attempt, allowed or denied, is audited; privileged
  executions produce a root-corroborated pair (§9).
- **P6** — The MCP surface never grants approval power (§10).
- **P7** — `sysh` weakens nothing on the host: it adds one system user, one
  `Match` block scoped to that user, and (opt-in) one sudoers line. It never
  edits global sshd settings or other users.

### Residual risks (accepted, named)

- **R1 — operator endpoint compromise.** Laptop malware holding the root SSH
  key can drive the control channel, including approvals (a TTY can be
  synthesized locally and fed to `ssh -t`). Mitigations: FIDO2 key for root
  (bounds *connection* auth to hardware), typed confirmations, audit
  corroboration. A hardware-touch-per-approval is a possible future
  extension, deliberately not in v1.
- **R2 — approval fatigue.** A human clicking through requests is the weak
  link; lockout, typed argv[0], and short TTLs bound but do not eliminate it.
- **R3 — `sysh-exec` is root-reachable attack surface.** It is intentionally
  minimal (fixed verbs, no shell, no path search, bounded parsing), but it
  must be treated as security-critical code: fuzzed, reviewed, static.
- **R4 — append-only audit relies on filesystem `+a`** where available;
  without it, a compromised agent can flood (not erase) the log.
- **R5 — policy globs are written by humans.** An over-broad `*` is an
  operator error `sysh` cannot undo; `sysh policy install` validates
  structure, not intent. (A lint pass is a possible addition.)

## 12. Explicitly rejected alternatives

- **Agent-side enforcement (prompt rules, harness policies):** the client is
  the adversary; enforcement must be where the adversary is not.
- **A management daemon / API plane:** another root-bearing service to
  defend, and a network channel where SSH already suffices.
- **chroot/jails/microVMs:** the product is *real host operation with least
  privilege*, not isolation.
- **Standing sudo with command allow-lists:** sudoers glob matching is
  string-based and famously bypassable; argv must be matched by code that
  sees the real argv, and elevation must be event-based, not standing.
- **Long-lived or reusable tokens:** every replay window is an attack window.
- **A second network protocol:** SSH is the protocol. Everything else is
  local commands.

## 13. Open questions for reviewers

- **Q1 — token transport.** `sysh-token gt_… -- argv` as a pseudo-command is
  explicit but puts the token in the command line (visible in `ps` on the
  server for the duration of the SSH exec, and in shell histories on the
  operator side). Alternatives: first-argv convention (`gt_… -- argv…`),
  or a stdin handshake (breaks one-shot scripting). Current lean:
  pseudo-command; token TTL is 120s and exposure is to the already-ssh-ed
  host's local process listing. Input wanted.
- **Q2 — `sy` UID write access to `/run/sysh/lockdown` and the audit file.**
  Both are deliberate (tripwire; self-audit) but are the only places the
  agent UID has a write handle. Confirm the appetite or propose hardening.
- **Q3 — sudoers vs setuid for `sysh-exec`.** Sudoers chosen for visibility
  in host configuration. Counter-arguments welcome.
- **Q4 — audit append-only strategy** on filesystems without `+a` (e.g.
  btrfs): accept flood-not-erase, or require forwarding to a remote sink
  from the start?
- **Q5 — pending-request recording via `sysh-exec`.** Recording requests
  through the privileged helper (vs. gateway-written) buys tamper-proof
  records at the cost of one extra sudo invocation per privileged request.
  Confirm the trade.
- **Q6 — key identity granularity.** Key comment as agent identity is weak
  (operator-chosen string). Is a required key-id in the authorized_keys line
  (enforced by `sysh auth add`) worth it?
- **Q7 — the `sy` tool.** Is even the minimal `keygen`+`mcp` helper the right
  cut, or should MCP live in a separate distribution entirely?

## 14. Implementation plan (after review approval)

1. `sysh` gateway: shell mode, policy engine, audit, builtins, lockdown.
2. `sysh-exec`: token verify, request-record, journal, corroboration.
3. Control subcommands: `auth add`, `policy install`, `approvals`,
   `approve`, `audit`, `doctor`.
4. Packaging: deb, postinst transaction, debconf tier question.
5. `sy keygen`, `sy mcp`.
6. Security review pass: fuzz `sysh-exec` parsers, audit the tokenization
   and glob matcher, verify ownership/mode conformance tests.
