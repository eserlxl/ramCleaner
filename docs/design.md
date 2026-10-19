# Design

ramCleaner finds processes that hold memory they no longer use, tells the user who really owns
them, and stops them only after the user approves. It never stops anything on its own.

## Why the existing tools miss this case

`earlyoom`, `nohang` and `systemd-oomd` act when memory runs out, and they kill without asking.
The case ramCleaner targets is slower: a daemon keeps one helper process per finished task, the
helpers sit idle, the kernel pushes them to swap, and available memory shrinks over days without
ever reaching an out-of-memory event. Desktop monitors group processes by the cgroup scope they
were started in, so a daemon launched from a terminal tab is shown as that terminal.

Reference incident: a Codex app-server daemon started from a Yakuake tab held 15 idle
context-mode MCP servers (`bun .../start.mjs`, about 0.6 GB each). Plasma System Monitor showed
"Yakuake 5 GB"; the group held 7 GB of RAM and 7 GB of swap.

## Data sources

All input is read from `/proc` and `/sys/fs/cgroup`. The roots are parameters (`proc_root`,
`cgroup_root`) so tests run against fixture trees.

Per process: pid, ppid, state (`/proc/PID/stat`), comm, cmdline, uid, `VmRSS`, `VmSwap`
(`/proc/PID/status`), cumulative CPU ticks (utime + stime) and start time, and the cgroup path
(`/proc/PID/cgroup`, the v2 `0::` line). Processes that vanish mid-scan are skipped, never an error.

Per cgroup: `memory.current` and `memory.swap.current`.

Only the invoking user's processes are considered.

## Owner attribution

The owner of a process is derived from its cgroup path, not its parent:

- `app-<appid>-<n>.scope` and `app-<appid>@<id>.service` → the application `<appid>`
  (for example `org.kde.yakuake`), with any `\x2d` escape decoded.
- a `tab(<pid>).scope` (Konsole/Yakuake) below such a scope adds the tab.
- `<name>.service` under `app.slice` or `session.slice` → the unit `<name>`.

A finding names both the owner and the process that is really responsible (the root of the
process subtree inside that cgroup), so the report can say "charged to org.kde.yakuake, held by
`codex app-server`".

## Detection rules

A scan takes two samples a few seconds apart (CPU ticks need a delta). Every rule yields findings
with an id, the processes involved, their RSS and swap, and a one-line reason.

1. **Idle clones.** Group processes by owner cgroup and by a command key (the executable plus the
   first script argument, so every `bun .../start.mjs` shares one key). A group is a finding when
   it has at least `min_clones` members (default 4) that are idle (no CPU ticks between the two
   samples), older than `min_age` (default 6 h), and whose RSS + swap totals at least
   `min_group_mb` (default 1024). Only the idle members are proposed for stopping.
2. **Unreaped zombies.** A zombie whose parent is alive and that has been a zombie in two scans in
   a row; the fix is on the parent, so the finding names the parent.
3. **Growth.** A process whose RSS + swap grew in every recorded scan over the history window
   (default 24 h, at least 4 scans) and by at least `min_growth_mb` (default 512). History lives in
   `$XDG_STATE_HOME/ramcleaner/history.json` (default `~/.local/state/ramcleaner/`), pruned to the
   window.

Processes in the protected list are never proposed: pid 1, the user's systemd manager, the
session compositor and shell (`kwin_wayland`, `plasmashell`, `ksmserver`), and ramCleaner itself.
The config can extend the list.

## Stopping

Stopping is per finding and only after approval.

- A **stop rule** in the config maps a command pattern to a graceful command, for example the
  Codex daemon's `codex app-server daemon stop`. Rules run first.
- Without a rule: SIGTERM to the listed pids, then wait up to `term_timeout` (default 10 s) and
  report which pids are still alive. SIGKILL only with an explicit `--force`.
- Before sending any signal, every pid is re-checked: same start time and same cmdline as in the
  scan. A pid that was reused is skipped.

## Interfaces

- `ramcleaner report` — memory by owner, then the findings. Read-only.
- `ramcleaner clean` — the findings, one `[y/N]` question each, then stops the approved ones.
- `ramcleaner watch` — one scan for the systemd user timer; each new finding becomes a desktop
  notification with "Stop" and "Ignore" actions (`notify-send --action`). "Ignore" suppresses
  that finding's key for `ignore_for` (default 24 h).

Configuration: `$XDG_CONFIG_HOME/ramcleaner/config.toml`, read with `tomllib`. Every key has a
default, so the file is optional.

## Constraints

- Python 3.11+ standard library only.
- Tests run with `python3 -B -m unittest discover -s tests` against fixture `/proc` and cgroup
  trees; no test reads the live system or sends a real signal.
