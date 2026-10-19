# Configuration

## Configuration file path

ramCleaner reads `$XDG_CONFIG_HOME/ramcleaner/config.toml` when `XDG_CONFIG_HOME` is set and non-empty, or `~/.config/ramcleaner/config.toml` otherwise.

The file is optional and parsed as UTF-8 TOML with Python's `tomllib`. Every key has a default. Unknown keys, invalid TOML syntax, or values of the wrong type cause ramCleaner to exit with status `2` before scanning.

## Configuration keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `min_clones` | integer (`>= 2`) | `4` | Minimum number of idle processes with the same owner cgroup and command key (`executable` and first non-option argument) required for an `idle-clones` finding. |
| `min_age_hours` | integer (`>= 0`) | `6` | Minimum process age in hours (`uptime - start_ticks / clk_tck > min_age_hours * 3600`) required for a sleeping or idle (`S` or `I`) process with zero CPU ticks between samples to count as an idle clone. |
| `min_group_mb` | integer (`>= 0`) | `1024` | Minimum combined `VmRSS + VmSwap` in MiB (`rss_kb + swap_kb >= min_group_mb * 1024`) across an idle clone group required to report an `idle-clones` finding. |
| `history_hours` | integer (`>= 1`) | `24` | Retention and lookback window in hours for `history.json` entries and `growth` detection. |
| `min_growth_mb` | integer (`>= 0`) | `512` | Minimum `VmRSS + VmSwap` increase in MiB across at least 5 samples (at least 4 recorded history scans within `history_hours` plus the current scan, with no step shrinking by more than 1%) required for a `growth` finding. |
| `term_timeout` | integer (`>= 0`) | `10` | Seconds to wait (polling `/proc/PID` every 0.2 s) after sending `SIGTERM` or running a stop rule before reporting surviving processes or sending `SIGKILL` under `--force`. `--force` sends `SIGKILL` only to processes that survived `SIGTERM`, never to a stop rule's survivors. |
| `ignore_for_hours` | integer (`>= 0`) | `24` | Hours to suppress a finding key in `ignored.json` when the notification is ignored or dismissed without clicking "Stop" in `ramcleaner watch`. An unanswered notification that reaches `ask_timeout_minutes`, or one `notify-send` could not show, is not suppressed and will be asked again on the next run. |
| `ask_timeout_minutes` | integer (`>= 1`) | `10` | Maximum minutes `ramcleaner watch` waits for all `notify-send` action notifications in a single pass (the popup's `--expire-time` is one minute longer, so `ramcleaner` ends the wait before the notification server closes it). Values `< 1` are rejected with a configuration error. |
| `other_users_min_mb` | integer (`>= 0`) | `512` | Minimum combined `VmRSS + VmSwap` in MiB (`rss_kb + swap_kb >= other_users_min_mb * 1024`) for an owner belonging to another user, including a root service, to appear in the `ramcleaner report` section `Other users (information only):`. Owners below the threshold are omitted, and the section is omitted when none qualify. These processes are never findings and are never stopped. |
| `protected` | array of strings | `[]` | Additional process `comm` names (from `/proc/PID/stat`) that are never reported or stopped. Extends the built-in protected set: PID `1`, the current `ramcleaner` process and its parent, and `comm` in `systemd`, `kwin_wayland`, `plasmashell`, and `ksmserver`. |
| `stop_rules` | array of `[pattern, command]` pairs, array of `{pattern, command}` tables, or table | `[]` | Ordered list of `(pattern, command)` pairs checked before sending `SIGTERM`. If `re.search(pattern, " ".join(cmdline))` matches any verified target process in the finding, `command` is split with `shlex.split` and run without a shell (60 s timeout) instead of signaling the PIDs directly. Every pattern must be a valid regular expression compilable by `re.compile`, and every command must be non-empty and parseable by `shlex.split`; invalid regex patterns, empty or whitespace commands, and unsplittable command strings (such as unbalanced quotes) are rejected with a configuration error. |

## `stop_rules` formats

`stop_rules` accepts three TOML shapes:

1. An array of two-string arrays:
   ```toml
   stop_rules = [
     ["\\.codex/plugins/cache/context-mode/.*/start\\.mjs", "codex app-server daemon stop"],
   ]
   ```
2. An array of tables with `pattern` and `command` keys:
   ```toml
   [[stop_rules]]
   pattern = "\\.codex/plugins/cache/context-mode/.*/start\\.mjs"
   command = "codex app-server daemon stop"
   ```
3. A table mapping regex pattern strings to command strings:
   ```toml
   [stop_rules]
   "\\.codex/plugins/cache/context-mode/.*/start\\.mjs" = "codex app-server daemon stop"
   ```

## Example: stopping the Codex `app-server` daemon cleanly

When the Codex `app-server` daemon leaves idle `context-mode` MCP helper processes (`bun .../context-mode/.../start.mjs`) running in a terminal tab, stopping the daemon cleanly with its own stop command closes the helpers without sending raw signals to individual child PIDs:

```toml
# ~/.config/ramcleaner/config.toml
min_clones = 4
min_age_hours = 6
min_group_mb = 1024
history_hours = 24
min_growth_mb = 512
term_timeout = 10
ignore_for_hours = 24
ask_timeout_minutes = 10
other_users_min_mb = 512
protected = []

stop_rules = [
  ["\\.codex/plugins/cache/context-mode/.*/start\\.mjs", "codex app-server daemon stop"],
]
```

When a finding's target processes match `\.codex/plugins/cache/context-mode/.*/start\.mjs` on `" ".join(cmdline)`, ramCleaner runs `codex app-server daemon stop` (split with `shlex.split`, timeout 60 s) and then polls `/proc/PID` for up to `term_timeout` seconds until the target processes exit.

Keep a pattern as narrow as the process it is meant for: Claude Code runs the same context-mode helper from `~/.claude/plugins/cache/`, and a bare `context-mode.*start\.mjs` would stop the Codex daemon when you approve stopping idle Claude helpers. The command runs without a shell, so `codex` must be on the `PATH` of the session that runs ramCleaner.
