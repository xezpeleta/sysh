# sysh

**A login shell for AI agents on servers.**

When you let an AI agent operate a server, you have two bad options today:
give it a root key (it can do anything, silently), or a normal user (it can do
nothing useful, still silently). `sysh` is the third option: the agent logs in
over plain SSH as an unprivileged system user whose *login shell* enforces an
allow-list of exact commands, records everything to an append-only audit log,
and — when a command genuinely needs root — stops and waits for a human to
approve a single, one-shot, expiring grant.

Control lives **on the server**, not in the agent's harness, not in a
management plane, not in prompt instructions. The agent cannot talk its way
past a shell.

## What it does

- **Privilege delimiting** — the agent may run exactly what the policy allows,
  as an unprivileged user. Policy is a signed TOML file; matching is on the
  literal argv, not on shell syntax (there is no shell).
- **Accountability** — every exec attempt (allowed or denied) is appended to a
  tamper-evident audit log, stamped with the invoking key and UID. Privileged
  runs get a corroborating root-side entry.
- **Ephemeral credentials** — privileged commands require a *grant token*:
  single-use, bound to the exact argv, expiring in ~2 minutes, minted only by
  a human typing an interactive confirmation on the server.
- **Human-gated elevation** — no standing sudo for the agent. One sudoers line
  invokes a verifier that only runs an argv whose token a human signed off on.

## What it is not

- **Not a sandbox.** The agent operates the real host, as a real (unprivileged)
  user, with the real tools. No jails, containers, or microVMs.
- **Not monitoring.** It audits its own gated channel. Fleet observability
  belongs to your existing stack.
- **Not an agent or a harness.** It works with any client that speaks SSH and
  can pass an argv — curl-driving scripts, CLI copilots, MCP servers, humans.
- **Not a replacement for human access.** Your own SSH is untouched.

## The whole lifecycle

```console
# sysadmin, on the server (everything local is done by the package):
root@server:~# apt install sysh            # creates the 'sy' user, host keypair,
                                           # /etc/sysh, audit log, sshd hardening
                                           # (privileged tier is a debconf question)

# operator, from their laptop, over plain SSH:
$ sy keygen server.example                 # or plain ssh-keygen; prints the line below
$ ssh root@server.example 'sysh auth add' <<<'restrict ssh-ed25519 AAAA… sy@laptop'
$ ssh root@server.example 'sysh policy install' < server.toml

# anyone the policy allows (human or agent):
$ ssh -i ~/.config/sysh/keys/server.example sy@server.example 'uptime'
[audit] sy allowed exec argv=["uptime"] via key sy@laptop

# a privileged command:
$ ssh -i … sy@server.example 'systemctl restart nginx'
approval_required: req_a1b2c3 (report this id; a human must approve)
$ echo $?                                 # → 30

# the human, interactively, on the server:
root@server:~# sysh approvals
req_a1b2c3  argv=["systemctl","restart","nginx"]  age=12s
root@server:~# sysh approve req_a1b2c3
type to confirm: systemctl                  # the binary name, from a TTY
token: gt_…                                 # bound to that exact argv, TTL 120s

# the agent retries with the token:
$ ssh -i … sy@server.example 'sysh-token gt_… -- systemctl restart nginx'
[audit] root exec argv=["systemctl","restart","nginx"] token=req_a1b2c3 approver=root
```

Every control operation above is a plain SSH command. There is no daemon, no
API, no management plane to defend, no agent-side anything.

## Design principles

1. **The server is the enforcement point.** Clients are untrusted transport.
2. **argv is the unit of trust.** No shell, no pipes, no `bash -c`, no
   heredocs through the gateway. Compound operations get their own allow-listed
   command, not a shell.
3. **No standing privilege.** Elevation exists only inside a verified,
   one-shot, argv-bound token execution.
4. **Zero elevation surface by default.** The base install contains no sudoers
   line, no setuid binary, nothing that can raise privileges. The privileged
   tier is a deliberate opt-in.
5. **Approvals are human and local.** Minting a token requires an interactive
   TTY on the server, a typed confirmation of the binary name, and reading the
   host-recorded (not agent-claimed) argv.
6. **Audit before everything.** Denials are logged as faithfully as successes.

## Security properties and honest limits

The threat model, adversary classes, and known residuals are written out in
[PROJECT.md](PROJECT.md). The short version: `sysh` defends against a
**compromised or misbehaving agent** (the `sy` account). It does not defend
against root compromise of the server, and it does not fully defend against
compromise of the operator's laptop — use a FIDO2 hardware-backed SSH key for
root access to shrink that window.

## Status

**Design phase — under review.** The specification in [PROJECT.md](PROJECT.md)
is complete and intended to be reviewed by engineers and security specialists
before implementation begins. No code has been written yet.

## License

MIT (see `LICENSE` once code lands).
