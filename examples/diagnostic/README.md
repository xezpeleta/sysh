# Example: read-only diagnostician

An agent policy for "look, don't touch": the agent can diagnose
problems on the host — processes, memory, disk, network, services,
files, packages — and cannot change anything, because **no mutating
tool has a rule**. The default is deny; read-only-ness here is not
enforced by blocking, it is enforced by omission.

What the agent gets, all journaled with full argv (paths included):

- **system**: uptime, id, hostname, uname, date, lscpu, lsusb, lsmod
- **processes**: ps (aux / -ef), top -bn1 (bounded by timeout)
- **memory/disk**: free, df, lsblk, du -sh, vmstat
- **network**: ss, `ip` read subcommands (addr/route/link/neigh —
  enumerated, so `ip addr add` cannot match), ping with a fixed
  count of 3
- **services**: `systemctl` query verbs only (status, is-active,
  is-enabled, show, list-units) — restart/stop/mask have no rule
- **files**: cat/grep/head/tail/stat/wc/file/ls/sha256sum over
  whatever `sy` can already read
- **packages**: dpkg -l, apt list --installed

## Deliberate exclusions (and why)

- **`env`** — it spawns commands (`env FOO=1 /anything`), which would
  bypass the argv policy. `printenv` covers the read use.
- **`find`** — `-exec` runs arbitrary argv and `-delete` mutates; its
  argument grammar is too rich for position patterns. `ls -laR` on
  specific trees, or an agent-script, covers the real cases.
- **`journalctl`** — reading the system journal needs the
  `systemd-journal` group (see `sysh journal-group enable` and the
  webserver example's ACL alternative). Opt in explicitly if you
  want it; this example stays group-free.
- **`docker` / other daemon CLIs** — read verbs through a group that
  owns the daemon socket (docker, libvirt…) are **root-equivalent**,
  not read-only. Never add them.
- **`curl`/`wget`/`nc`** — network egress plus file writes (`-o`);
  out of scope for a diagnostician.

## Honest limits

- The agent reads everything **`sy` can read**. Keep `sy` out of
  `adm`, `sudo`, `docker`, `systemd-journal` (doctor's group check
  enforces the dangerous ones). What world-readable files leak is a
  pre-existing host property, not something this policy widens.
- Exfiltration of what was read is inherent to giving an agent SSH;
  the journal's argv record (every path it cat'd) is the audit
  trail for what was looked at.
- Long-running reads are bounded per rule (`timeout`) and by the
  output cap.

## Install

```console
# on the host, as root:
sysh policy lint < policy.toml   # expect clean, read the infos
sysh policy install < policy.toml
sysh doctor
```

Then from the agent side: `ssh sy@host 'systemctl status docker'`
works, `ssh sy@host 'systemctl restart docker'` is refused with the
list of what exists (`sy-policy`). Extend by adding rules — one
verb, one decision, each one a line you can point at in review.
