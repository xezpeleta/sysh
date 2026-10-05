# Example: operational agent with approvals

The middle point between the read-only diagnostician and the
web-server maintainer: the agent **diagnoses freely and acts only
with a human in the circuit**. Every mutating verb goes through the
approval channel — there is no standing root grant for anything
disruptive.

## The three ways a verb can exist

1. **Standing grant** — the only one here: `systemctl daemon-reload`
   (re-reads unit files from disk; restarts nothing, disrupts
   nothing). Root, no approval, because it is genuinely inert.
2. **Approval channel** — `systemctl restart <unit>`,
   `systemctl reload <unit>`, `apt-get update`: privileged +
   `approval = true`. The agent can *request*, never *run*.
3. **No rule** — everything else (`apt-get upgrade`, `tee` on
   configs, `reboot`…): denied, not blocked — just absent.

## The ceremony (what a real incident looks like)

```console
# agent (anywhere, key sy/…):
$ ssh sy@host '/usr/bin/systemctl status docker'
  … active (running) …            # free: observe
$ ssh sy@host '/usr/bin/systemctl restart docker'
  {"class":"approval_required","request_id":"req_1a2b3c4d5e6f", …}
  exit 30                          # the request waits, nothing ran

# operator (a root SSH session ON the host):
# sysh approvals
  request req_1a2b3c4d5e6f
    key:  sy/prod-agent (claimed)
    argv: ["/usr/bin/systemctl","restart","docker"]
    rule: 13, timeout 60s
# sysh approve req_1a2b3c4d5e6f
  execute as root? [yes/no] yes
  type argument 2 exactly as shown (docker): docker
  approved by operator (rule 13)

# agent picks up the outcome:
$ ssh sy@host 'sysh-result req_1a2b3c4d5e6f'
  {"class":"exec","exit":0, …}     # it ran, as root, contained
```

Properties worth knowing:

- **The approver types the pattern-chosen argument by hand**
  (`docker` above). Pattern positions are the only
  attacker-influenced content; a fully literal rule (`apt-get
  update`) asks for a plain `yes` instead.
- **Approval chooses *when*; policy chooses *what*.** The root-side
  `sysh approve` re-matches the argv against the installed policy —
  an operator cannot approve anything the policy does not
  authorize, whatever the request file claims.
- **Requests expire**: TTL is 10 minutes; expired requests are
  removed on sight. A repeated identical request (same argv + key)
  renews the existing entry instead of piling up.
- **Remote approval** without a root session on the host:
  `sysh approve <id> --show` prints the exact request bytes; sign
  them with `ssh-keygen -Y sign -f <approver-key> -n sysh-approve`
  and submit `sysh approve <id> --sig < file.sig`. The signature
  must be from a registered approver key; for sk-* hardware keys
  the touch happened at sign time — that is the human in the loop.
- **The gateway never elevates.** It only writes a file into the
  drop box it is allowed to write, so NoNewPrivs holds for the
  agent channel at all times; the root side executes.

## Honest limits

- `systemctl restart` over a *pattern* means the agent can request a
  restart of any unit; the human typing the unit name is the check
  on which unit. If you would rather bound it, enumerate units as
  literal argv — one rule per unit, nothing to type.
- Approvals do not bound *why*. The journal records the request,
  the approver, and the exec pair; the judgment is the human's.
- `daemon-reload` being inert is a systemd property, not a sysh
  one — re-check it against your version if you keep the standing
  grant.

## Install

```console
# on the host, as root:
sysh policy lint < policy.toml   # expect clean
sysh policy install < policy.toml
sysh doctor
```

To extend with writes (config files through `tee`, validate-then-
reload pairs), see `examples/webserver` — the same approval
mechanism, plus standing grants for the write side.
