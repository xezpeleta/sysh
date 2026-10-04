# Example: agent-maintained web server (Apache + fail2ban)

A worked example of the "attended setup, unattended operation" workflow
for a typical Debian/Ubuntu web server. The agent ends up able to:

- **observe**: uptime, disk, memory, service status, the journal,
  apache/fail2ban logs;
- **customize Apache**: read the whole config tree, write the enumerated
  config files (content on stdin through `tee`), validate with
  `apache2ctl configtest`, reload the service; a full **restart is
  approval-gated** — the agent can only request it (exit 30) and a
  human answers `sysh approve` from any root SSH session;
- **customize fail2ban**: write `/etc/fail2ban/jail.local`, restart it;
- **nothing else** — `sudo`, `su`, and every unlisted argv are denied.

It is deliberately *not* a general-purpose admin policy. Delete rules
you do not want, add the exact files for your own vhosts, and treat
`policy install` (with its linter) as the gate.

## OS-side setup (attended, once, as root)

The argv policy bounds the verbs; these steps define the objects.

1. **Log reads — ACLs, not groups.** The apache and fail2ban logs are
   `root:adm 0640`; adding `sy` to `adm` would be over-broad (and the
   `doctor` group check rejects it). Give `sy` read on exactly these:

   ```console
   # apache logs + inheritance across logrotate rotations
   setfacl -m u:sy:rX /var/log/apache2
   setfacl -m u:sy:r /var/log/apache2/access.log
   setfacl -m u:sy:r /var/log/apache2/error.log
   setfacl -d -m u:sy:r /var/log/apache2

   # fail2ban log
   setfacl -m u:sy:r /var/log/fail2ban.log
   ```

   The default ACL (`-d`) makes newly rotated files inherit `sy`'s read.

2. **Journal reads — the documented opt-in:**

   ```console
   sysh journal-group enable
   ```

3. **Privileged rules need sudo >= 1.9.13** (Debian 12's 1.9.13p3 is
   fine). Install checks and refuses otherwise, and generates the
   sudoers fragment `/etc/sudoers.d/60-sysh` (root-owned 0440) with one
   `TIMEOUT=<n> NOPASSWD` line per privileged rule. Run
   `sysh policy install policy.toml` and confirm with `sysh doctor`.

No extra supplementary groups are needed for this profile (ACLs carry
the log reads), so the `doctor` group tripwire stays clean.

## What the agent session looks like

```console
$ ssh -i agent.key sy@web01.example.net '/usr/sbin/apache2ctl configtest'
  Syntax OK                                      # privileged, PRIV=true
$ cat new-vhost.conf | ssh -i agent.key sy@web01.example.net \
    '/usr/bin/tee /etc/apache2/sites-available/000-default.conf'
$ ssh -i agent.key sy@web01.example.net '/usr/bin/systemctl reload apache2'
$ ssh -i agent.key sy@web01.example.net \
    '/usr/bin/tail -n 50 /var/log/apache2/error.log'
```

## Honest trade-offs, stated

- **The tee grants bound where, not what.** The agent controls the
  content it pipes into the enumerated files. That is the deal: you
  pre-authorized writes to those files; the record shows exactly what
  was written and when. `apache2ctl configtest` being in the policy is
  convention, not enforcement — the agent *can* reload a broken config.
  Keep `doctor` and the journal in your routine.
- **NNP is off on this host** while privileged rules exist (PROJECT.md
  §6.8): the exact-argv sudo grants are the only elevation surface.
- **Patterns are fine in unprivileged rules** (anchored, per-position)
  and **in approval rules** (the human re-checks what matched and types
  the pattern-chosen values at `sysh approve`) — but never in
  pre-authorized privileged ones: sudoers grants are exact argv, so
  root verbs are enumerated file by file.
- Restart verbs carry `TIMEOUT=` in the generated grant: a wedged
  restart dies at the deadline, and sudo (not the agent) kills it.
  Approval-gated verbs carry the same bound on the root-side execution.
- **Approval-gated restart (apache2) generates no sudoers grant at all**:
  while the request waits, root simply cannot be reached through this
  argv; after a human answers, the one execution runs in a root-side
  systemd scope — and both halves land in the journal (`request` at
  `_UID=999`, `approve` at `_UID=0`).

## Verify it

```console
sysh doctor                      # 0 failures, 0 warnings
journalctl -t sysh --since today # every attempt, both phases
ausearch -k sysh_exec            # kernel-side: files touched
```
