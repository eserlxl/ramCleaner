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

Per cgroup: the `anon` line of `memory.stat`, `memory.swap.current`, and `memory.zswap.current` (0
when absent on kernels without zswap). RAM means anonymous memory; reclaimable page cache is
excluded, and zswap is the compressed share of swap still held in RAM, reported separately from RAM
and swap. Those counters include every descendant cgroup. Exclusive charges are computed bottom-up,
deepest owner first, so each readable ancestor subtracts the exclusive RAM, swap, and zswap of nested
owners once. When an owner cgroup's `memory.stat` or `memory.swap.current` cannot be read, its row
falls back to the summed `VmRSS` and `VmSwap` of processes in that owner's own bucket. That bucket
excludes deeper owner buckets. A readable ancestor still subtracts those exclusive charges once,
whether the nested owner is an unreadable grandchild or an unreadable intermediate child above a
readable grandchild. The fallback includes file-backed pages. The report appends
`VmRSS: cgroup memory unreadable` only on the unreadable row, and zswap on that row is 0.

Only the invoking user's processes are considered.

## Owner attribution

The owner of a process is derived from its cgroup path, not its parent:

- `app-<appid>-<n>.scope` and `app-<appid>@<id>.service` → the application `<appid>`
  (for example `org.kde.yakuake`), with any `\x2d` escape decoded.
- a `tab(<pid>).scope` (Konsole/Yakuake) below such a scope is its own owner, "`<appid>` tab
  `<pid>`": each tab runs unrelated work, and a daemon started from a tab stays in it.
- `<name>.service` under `app.slice` or `session.slice` → the unit `<name>`.

Each report row names both the owner and the process that is really responsible (the root of the
heaviest process subtree inside that cgroup, followed down to the child holding most of it), so the
report can say "charged to org.kde.yakuake, held by `codex app-server`".

## Detection rules

A scan takes two samples `--interval` seconds apart (default 2.0; CPU ticks need a delta).
Every rule yields findings
with an id, the processes involved, their RSS and swap, and a one-line reason.

1. **Idle clones.** Group processes by owner cgroup and by a command key (the executable plus the
   first script argument, so every `bun .../start.mjs` shares one key). A group is a finding when
   it has at least `min_clones` members (default 4) that are idle (no CPU ticks between the two
   samples), older than `min_age_hours` (default 6 h), and whose RSS + swap totals at least
   `min_group_mb` (default 1024). Only the idle members are proposed for stopping. The reason
   names a short command: the executable plus the script basename when that basename has no
   whitespace and is at most 40 characters (`bun start.mjs` stays; `python3 -c` code becomes
   `python3`). It then says the youngest member has been `running for at least` a whole number of
   minutes under 1 h, hours under 48 h, otherwise days. The finding key keeps the full command
   key, so the shorter reason does not change `ignored.json`. Chromium and Electron child
   processes (a `--type=` argument) and Firefox content processes (`-contentproc`) are never
   clones: each is an open tab or window.
2. **Unreaped zombies.** A zombie whose parent is alive and that has been a zombie in two scans in
   a row; the fix is on the parent, so the finding names the parent.
3. **Growth.** A process whose RSS + swap grew by at least `min_growth_mb` (default 512) over the
   `history_hours` window (default 24 h, at least 4 recorded scans plus the current sample) with no
   step shrinking by more than 1 % of the previous size. Chromium and Electron child processes (a
   `--type=` argument) and Firefox content processes (`-contentproc`) are excluded. History lives in
   `$XDG_STATE_HOME/ramcleaner/history.json` (default `~/.local/state/ramcleaner/`), pruned to the
   window. When `/proc/sys/kernel/random/boot_id` is readable, growth and zombie persistence use
   only history entries from that boot; entries from another boot, or recorded without a boot id,
   are ignored. When that boot id is known, zombie and growth suppression keys are
   `zombie:<boot_id>:<pid>:<start_ticks>` and `growth:<boot_id>:<pid>:<start_ticks>`; without one
   they stay `zombie:<pid>:<start_ticks>` and `growth:<pid>:<start_ticks>`. Idle-clones keys name an
   owner cgroup and command and stay independent of the boot. An `ignored.json` entry in the
   previous zombie or growth form stops matching and expires, so the finding is asked once more.

Processes in the protected list are never proposed: pid 1, the user's systemd manager, the
session compositor and shell (`kwin_wayland`, `plasmashell`, `ksmserver`), and ramCleaner itself.
The config can extend the list.

## Stopping

Stopping is per finding and only after approval.

- A **stop rule** in the config maps a regex pattern (matched with `re.search` against
  `" ".join(cmdline)`) to a graceful command, for example the Codex daemon's
  `codex app-server daemon stop`. Rules run first (split with `shlex.split`, never a shell,
  60 s timeout) without sending a signal.
- Without a rule: SIGTERM to the listed pids, then poll `/proc/PID` every 0.2 s up to
  `term_timeout` (default 10 s) until each pid has exited (its `/proc/PID` directory is gone, its
  `start_ticks` changed, or its state is `Z`) and report which pids are still alive. A `start_ticks`
  change during that wait is an exit. With an explicit `--force`, post-grace re-check each survivor
  and send SIGKILL only when `start_ticks` and cmdline still match the scan and the process is not
  protected, then poll up to 2 s more. `PermissionError` on SIGTERM or SIGKILL skips that pid as not
  permitted and continues with the remaining pids; that pid is neither stopped nor still alive.
- Before sending any signal, a pidfd is opened for each pid and its `/proc/PID` entry is
  re-checked: same start time (`start_ticks`) and same cmdline as in the scan, and not protected.
  Signals (`SIGTERM` and `--force` `SIGKILL`) are sent through that pidfd. After the grace period
  the same identity and protection are read again before SIGKILL; a `start_ticks` or cmdline
  mismatch is skipped as pid reuse, and a protected comm is skipped as protected. A residual exec
  window remains between that re-read and SIGKILL in which the same task can exec. A pid that
  vanished, was reused, or is protected before the first signal has its pidfd closed and is skipped.

## Interfaces

- `ramcleaner report` — memory by owner, then the findings. Reads history without writing it;
  `--history-file` overrides the default state path. While fewer than 4 watch scans are recorded
  within `history_hours`, a note on stderr says growth checks need 4 and zombie checks need 1.
- `ramcleaner clean [--force]` — the findings, one `Stop it? [y/N/d] ` question each (`d` lists the
  finding's processes and asks again), then stops the approved ones. Refuses with exit 2 if stdin is
  not a tty; exits 0 when nothing is approved or every approved stop leaves no survivors, and 1 if
  any survivor remains. Prints the same short-history note as `report`.
- `ramcleaner ignored [--clear]` — lists the findings `watch` has suppressed in `ignored.json`, or
  with `--clear` empties the file under `watch.lock` so the next run asks again.
- `ramcleaner watch` — one scan for the systemd user timer (`ramcleaner-watch.timer` and
  `ramcleaner-watch.service`, `Type=oneshot` with `TimeoutStartSec=infinity`); guarded by
  `watch.lock`, records history, and turns each new finding into a desktop notification with "Stop"
  and "Ignore" actions (`notify-send --expire-time --action`), waiting against a shared
  `ask_timeout_minutes` deadline (default 10 min). Timed-out notifications are killed, and like
  unavailable notifications (`notify-send` could not show them) they neither stop nor suppress the finding (it is
  asked again on the next run); only "Ignore" or a dismissal suppresses that finding's key in
  `ignored.json` for `ignore_for_hours` (default 24 h).

`bin/ramcleaner` locates the package in `../lib/ramcleaner` when installed via `Makefile` or in the
repository root when run from a checkout.

Configuration: `$XDG_CONFIG_HOME/ramcleaner/config.toml`, read with `tomllib`. Every key has a
default, so the file is optional.

## Constraints

- Python 3.11+ standard library only.
- Tests run with `python3 -B -m unittest discover -s tests` against fixture `/proc` and cgroup
  trees; no test reads the live system or sends a real signal.
