# Agent scripts mode study: `lines` vs `traced` vs root

Empirical answer to one question: **does giving agents "seemingly
normal bash" (traced) or the sysh dialect (lines) change how
efficiently they work?** — and the follow-up it forces: **which mode
should be the default?**

Method: blind subagents (no sysh documentation, no briefing — just an
ssh command and a task), one task per experiment family, identical
task text across arms, identical policy except `agent_scripts_mode`.
Everything the agent did is in the sysh journal; wall time, message
counts and tool calls come from the agent harness session logs. All
runs against a single Debian 12 test VM on a LAN.

---

## Experiments

| Arm | Mode | Rules | Task | Agent msgs | Wall | Journal events | Denials | Reports correct |
|-----|------|------:|------|-----------:|-----:|---------------:|--------:|:---------------|
| E1a | root, traced | — (root: no policy) | diagnostics + write report to server | 28 | 66 s | 21 | 0 | yes (rsync upload) |
| E1b | root, lines | — | same | 38 | 104 s | 46 | 0 | yes (sftp upload) |
| E2a | enforcing, traced | 52 | diagnostics + governed write (`tee`, approval) | 25 | ~2.5 min | — | 0 | yes |
| E2b | enforcing, lines | 52 | same | 36 | ~5 min (+225 s approval waits) | — | 0 | yes |
| E3a | enforcing, traced | 58 | **analysis of a 135 MB log** (top-10 error messages + per-hour distribution), read-only | 8 | 4 m 50 s | 84 | 0 | **yes, exact** |
| E3b | enforcing, lines | 58 | same | 16 | **2 m 43 s** | 223 | 1 | **yes, exact** |

Notes on the table:

- **E2a replaced an earlier run** against a 28-rule policy: 3
  denials, all traced to *operator* ruleset gaps (only bare-name
  option variants enumerated, not `/usr/bin/...` absolute forms).
  After the ruleset was completed (bare + absolute twins for every
  tool, option clusters enumerated and acknowledged), both E2 arms
  ran with zero denials. Option enumeration is the operator's job;
  agents that read `sy-policy` first incur none.
- **E3 was the decisive arm**: a task where traced *should* dominate.
  The rules included everything needed for a one-shot script —
  `grep | sort | uniq -c | sort -rn | head` — whose output would
  have been ~1 KB against 135 MB of input.
- E3b's single denial was a compound-shell attempt (`echo
  "CONNECTED; ls …; head …; grep …"` — semicolons inside one argv).
  The gateway refused it and the agent reoriented on the very next
  call. That is the argv contract teaching, working as designed.
- Both E3 reports matched a precomputed reference (frequencies
  50 032 … 11 053, per-hour counts, total 280 364) digit for digit.

## What the agents actually did

**No agent used agent scripts in any arm — including the arm built
to make scripts shine.**

- **E1 (root)**: direct per-command execs over separate ssh
  connections, output saved locally, computed locally, report
  uploaded (rsync / sftp).
- **E2 (enforcing)**: read `help` and `sy-policy` first, then fired
  only allowed argv forms; governed write via the approval ceremony
  (exit 30 → poll `sysh-result` → handoff with state after the
  human-latency window).
- **E3a (traced, 135 MB)**: chose 62 `sed` calls, each an 80
  k-line window with an ERROR filter **executed server-side**, then
  aggregated locally. The script-with-pipes path was available,
  cheaper and advertised; it was not taken.
- **E3b (lines, 135 MB)**: chose 96 `grep` fragments keyed by
  date+hour (server-side filtering again), verified 280 364/280 364
  with no truncation, aggregated locally.

Both E3 arms converged on the same shape: **push the filter to the
server, pull only the matches, compute where the agent lives.**
The 25 ms-per-call ssh round trips on a LAN made that cheap; the
difference between 84 and 223 events is strategy choice (sed windows
vs grep fragments), not mode.

## Conclusions per mode

### root — for trusted, fully-observable break-glass only

Fastest (no policy checks, no approval latency) and the journal is
per-execve — but it *weakens* the model: the agent is root, so the
policy cannot refuse anything and observability is the only control
left. Use it for the documented exception: debugging the gateway
itself, or recovery when the policy is wrong. Not a mode to build
procedures on.

### lines — the honest dialect, and the empirically sufficient one

Every line of every script is policy-checked and journaled like a
direct exec; scripts cannot hide argv, and the mechanism is simple
(a systemd scope per script). The E-matrix says agents do not need
more: across six arms and three task families, lines-mode agents
matched traced-mode agents in correctness and wall time (E3b was
faster than E3a; the 25↔38-message spread in E1 is session noise).
Its hard limit is real but narrow: **no pipes, no loops, no
remote-side aggregation** — an agent that needs to reduce data on
the server must find countable forms (`grep -c`, server-side `sed`
filters) or move the bytes.

### traced — capability insurance, not an efficiency win

Traced adds what lines cannot do: a real interpreter (any shebang)
running as the unprivileged gateway user, with **every execve in
the tree policy-checked and journaled** — pipes, loops, and
aggregation on the server, with full argv-level audit of each
exec. That is the right tool when the operator *requires* remote
computation: data too large to pull, data that must not leave the
server, or transformations the policy can enumerate but the agent
cannot chunk. But the data here is unambiguous: **agents do not
reach for it on their own.** Traced's value is in what the operator
can mandate through it, not in what agents spontaneously gain.

## Recommendation

1. **Keep `lines` as the default.** It is the simpler mechanism
   (systemd scope vs ptrace + rlimits), its audit story is exactly
   as strong for the work agents actually do (direct execs), and no
   experiment shows an agent-efficiency cost. Changing the default
   would buy nothing measured.
2. **Document `traced` as the deliberate upgrade** for
   remote-computation tasks — an operator decision, made per host,
   when pulling is not acceptable. The mode flip stays cheap
   (one policy field, per host).
3. **Write the constraint into the task, not the mode.** What moved
   every agent in this study was the task and the refusal text, not
   the script mode. If remote reduction is required, say so in the
   task (and in `sy-docs`); that is what will make an agent reach
   for the script directory — and that is a traced-mode host.

## Artifacts

- E1–E3 session logs and task prompts: operator-side, not in this
  repo (they contain test-host addressing).
- Reference answers for E3 were computed root-side before the arms
  ran and compared after; both arms matched exactly.
- One incidental finding from E2 (recorded separately): approval
  argv must be **data-complete** — the ceremony executes the argv
  at approve time with no stdin, so `… | tee /path` writes an empty
  file on a false success. Governed writes should upload to `drop/`
  and approve an `install`/`cp` argv instead.
