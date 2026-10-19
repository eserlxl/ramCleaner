# CLI Reference

## Synopsis

```text
usage: ramcleaner [-h] [--proc-root PROC_ROOT] [--cgroup-root CGROUP_ROOT]
                  [--version]
                  {report,clean,watch,ignored} ...

Report memory usage attributed to owning applications and units.

positional arguments:
  {report,clean,watch,ignored}
    report              Print memory usage grouped by owning application or
                        unit.
    clean               Interactively approve and stop reported findings.
    watch               Scan once, record history, and notify about new
                        findings.
    ignored             List or clear active watch suppressions.

options:
  -h, --help            show this help message and exit
  --proc-root PROC_ROOT
                        Path to /proc root (test aid; default: /proc).
  --cgroup-root CGROUP_ROOT
                        Path to cgroup v2 root (test aid; default:
                        /sys/fs/cgroup).
  --version             show program's version number and exit
```

`ramcleaner --version` prints `ramcleaner <version>` and exits `0` without scanning.

`--proc-root` and `--cgroup-root` are also accepted after `report`, `clean` and `watch` for test fixtures.

## Subcommands

### `ramcleaner report`

```text
usage: ramcleaner report [-h] [--interval INTERVAL]
                         [--history-file HISTORY_FILE] [--top TOP]

options:
  -h, --help            show this help message and exit
  --interval INTERVAL   Seconds between CPU samples (default: 2.0).
  --history-file HISTORY_FILE
                        History file to read (default: XDG state directory).
  --top TOP             Maximum number of owners to display (default: 15).
```

Takes two process samples `--interval` seconds apart, prints `RAM = anonymous memory, page cache excluded`, prints up to `--top` owner rows sorted by total memory (`RAM + swap`) descending, and then prints `Findings:` followed by each finding or `Findings: none`.

`report` reads `--history-file` if it exists (for `zombie` and `growth` detection) and never creates or modifies state files. When fewer than 4 recorded scans in `--history-file` fall within `history_hours` of now, `report` prints an advisory note to `stderr` after the findings (`Note: <n> of 4 watch scans in the last <h> h; growth checks need 4 and zombie checks need 1, recorded by the ramcleaner-watch timer`).

### `ramcleaner clean`

```text
usage: ramcleaner clean [-h] [--interval INTERVAL]
                        [--history-file HISTORY_FILE] [--force]

options:
  -h, --help            show this help message and exit
  --interval INTERVAL   Seconds between CPU samples (default: 2.0).
  --history-file HISTORY_FILE
                        History file to read (default: XDG state directory).
  --force               Send SIGKILL to processes that survive SIGTERM.
```

Requires an interactive terminal (`sys.stdin.isatty()`). Takes two samples `--interval` seconds apart and prints `Findings: none` when nothing is detected.

For each finding, `clean` prints the finding line and prompts `Stop it? [y/N/d] `. Answering `d` or `details` prints one line per process in the finding (`  <pid>  <rss+swap MB> MB  <' '.join(cmdline) or comm>`) and re-prompts. Only `y` or `yes` (case-insensitive) approves stopping; any other input or `EOF` skips the finding. After stopping an approved finding, `clean` prints:

```text
method=<method>  stopped=<pids>  still_alive=<pids>  skipped=<pid (reason), ...>
```

`clean` reads `--history-file` without modifying it. When fewer than 4 recorded scans in `--history-file` fall within `history_hours` of now, `clean` prints the same advisory note to `stderr` after the findings.

### `ramcleaner watch`

```text
usage: ramcleaner watch [-h] [--interval INTERVAL]
                        [--history-file HISTORY_FILE]

options:
  -h, --help            show this help message and exit
  --interval INTERVAL   Seconds between CPU samples (default: 2.0).
  --history-file HISTORY_FILE
                        History file to read and append each scan to (default:
                        XDG state directory).
```

Runs a single scan pass intended for `ramcleaner-watch.service`:

1. Opens `watch.lock` in the parent directory of `--history-file` and takes a non-blocking exclusive lock (`fcntl.flock` with `LOCK_EX | LOCK_NB`). If another `watch` process holds the lock, prints `another watch is running` to `stderr` and exits `0`.
2. Loads `history.json`, takes two process samples `--interval` seconds apart, runs detection, and atomically appends the current scan to `history.json` (pruning entries older than `history_hours`).
3. Loads `ignored.json` from the same state directory and filters out findings whose suppression timestamp is in the future (`until > now`).
4. Prints each unsuppressed finding to `stdout` and starts `notify-send --app-name=ramCleaner --urgency=normal --expire-time=<(ask_timeout_minutes * 60 + 60) * 1000> --action=stop=Stop --action=ignore=Ignore` concurrently for all unsuppressed findings, waiting against a shared `ask_timeout_minutes` deadline (default `10` minutes). Any `notify-send` process still running at the deadline is killed and reaped with outcome `"timeout"`.
5. For each finding where the user clicked `Stop`, stops the finding (without `--force`) and sends a follow-up informational notification summarizing the result. That notification waits at most 10 seconds; after that `notify-send` is killed and a `Warning:` line is printed, without changing the stop result or the exit status. For each timed-out finding (`"timeout"`), prints `<owner_label>: no answer, will ask again` to `stdout` without stopping or suppressing it. When `notify-send` is unavailable or fails (`"unavailable"`), prints `<owner_label>: notification unavailable, will ask again` and likewise neither stops nor suppresses the finding, since the user never saw it. For every other answer (`Ignore` or notification closed), records `now + ignore_for_hours * 3600` in `ignored.json`.

### `ramcleaner ignored`

```text
usage: ramcleaner ignored [-h] [--history-file HISTORY_FILE] [--clear]

options:
  -h, --help            show this help message and exit
  --history-file HISTORY_FILE
                        History file whose directory holds ignored.json and
                        watch.lock (default: XDG state directory).
  --clear               Clear all suppressed findings.
```

Lists or clears findings suppressed by `ramcleaner watch`:

- Without `--clear`, reads `ignored.json` from the parent directory of `--history-file` and prints one `<key>  until <local ISO time>` line per entry whose expiry is in the future. Expired entries are omitted. If there are no active suppressions or `ignored.json` does not exist, prints `Suppressed findings: none`.
- With `--clear`, takes a non-blocking exclusive lock on `watch.lock` in the parent directory of `--history-file`. If another `watch` process holds the lock, prints `another watch is running` to `stderr` and exits `1`. Otherwise, empties `ignored.json` and exits `0`.

Neither mode touches `history.json`.

## State files

By default, state files live in `$XDG_STATE_HOME/ramcleaner/` when `XDG_STATE_HOME` is set and non-empty, or `~/.local/state/ramcleaner/` otherwise. Passing `--history-file PATH` places `ignored.json` and `watch.lock` in `PATH`'s parent directory.

| File | Written by | Purpose |
| --- | --- | --- |
| `history.json` | `ramcleaner watch` | JSON array of scan records `{"time": <float>, "procs": {"<pid>:<start_ticks>": <rss_kb + swap_kb>}, "zombies": ["<pid>:<start_ticks>"], "boot_id": "<string>"}`; `"boot_id"` is written when `/proc/sys/kernel/random/boot_id` is readable and omitted otherwise, and records without it still load. Retained for `history_hours` (default `24` h). Read by `report`, `clean`, and `watch`. |
| `ignored.json` | `ramcleaner watch`, `ramcleaner ignored --clear` | JSON object `{"<finding.key>": <expiry_timestamp>}` tracking findings suppressed for `ignore_for_hours` (default `24` h). Zombie and growth keys are `zombie:<boot_id>:<pid>:<start_ticks>` and `growth:<boot_id>:<pid>:<start_ticks>` when a boot id is known, and `zombie:<pid>:<start_ticks>` and `growth:<pid>:<start_ticks>` when it is not. Idle-clones keys do not include a boot id. Entries stored in the previous zombie or growth form stop matching and expire, so the finding is asked once more. Expired entries (`until <= now`) are pruned when saved. Read and cleared by `ignored`. |
| `watch.lock` | `ramcleaner watch`, `ramcleaner ignored --clear` | Advisory `flock` lock file preventing overlapping `ramcleaner watch` runs or suppression clearing. |

If `history.json` or `ignored.json` is malformed or unreadable, ramCleaner prints a `Warning:` line to `stderr` and treats the file as empty.

## Exit statuses

| Exit status | Meaning |
| --- | --- |
| `0` | Success: `report` completed; `ignored` listed active suppressions or emptied `ignored.json`; `clean` or `watch` had no findings, no finding was approved, another `watch` held `watch.lock`, or every approved stop left no surviving processes (`still_alive` is empty). |
| `1` | Partial stop or lock collision: at least one approved finding in `clean` or `watch` still had surviving target processes (`still_alive` is non-empty) after waiting for exit; or `ramcleaner ignored --clear` found `watch.lock` held by another watch process. |
| `2` | Usage or configuration error: invalid CLI arguments (including negative or non-finite `--interval`), invalid or unreadable `config.toml`, or `ramcleaner clean` run when `stdin` is not a TTY. |
