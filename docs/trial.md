# Desktop trial

This guide runs ramCleaner from a git checkout and exercises the notification **Stop**, **Later**, **Hide...**, and **Details...** actions on purpose-built idle processes. It does not use a real workload and does not enable `ramcleaner-watch.timer`.

Every ramCleaner command below passes `--history-file /tmp/ramcleaner-trial/history.json`. `history.json`, `ignored.json`, and `watch.lock` are created only in that directory. The default state directory (`$XDG_STATE_HOME/ramcleaner`, or `~/.local/state/ramcleaner` when `XDG_STATE_HOME` is unset) is left untouched.

`ramcleaner watch` needs a running notification daemon and `notify-send` with `--action` support. **Hide...** uses `zenity` for the duration menu; without `zenity` that button hides the finding for `ignore_for_hours` and prints one `Warning:` line. **Details...** uses `zenity` for one checklist of the stoppable findings in that run. Requirements are listed in [installation.md](installation.md).

## Throwaway directory

```sh
mkdir -p /tmp/ramcleaner-trial/config/ramcleaner
printf '%s\n' 'min_age_hours = 0' > /tmp/ramcleaner-trial/config/ramcleaner/config.toml
export XDG_CONFIG_HOME=/tmp/ramcleaner-trial/config
```

The throwaway file sets only `min_age_hours`. `min_clones` stays at its default of 4 and `min_group_mb` stays at its default of 1024. A process joins an idle-clones group only when its age is greater than `min_age_hours` hours; the built-in default is 6, so processes started in the next step would not qualify until then. `min_age_hours = 0` means age must be greater than 0. The real configuration (`~/.config/ramcleaner/config.toml`, or a `XDG_CONFIG_HOME` value already set in the shell) is not modified.

Run the ramCleaner commands in this same shell so they keep that `XDG_CONFIG_HOME`. When this shell already depended on another `XDG_CONFIG_HOME`, restore that value after the trial (closing the shell drops the export).

## 1. Report and clean

From the repository root. At each `Stop it? [y/N/d] ` prompt, answer `n` so `clean` skips the finding and stops nothing:

```sh
./bin/ramcleaner report --history-file /tmp/ramcleaner-trial/history.json
./bin/ramcleaner clean --history-file /tmp/ramcleaner-trial/history.json
```

`report` and `clean` do not create or modify the history file. `Findings: none` means `clean` does not prompt.

## 2. Idle clones, Hide, then Stop

Open one dedicated terminal tab and leave it open. Idle-clones groups processes that share an owner cgroup and a command key (the executable plus the first argument that does not start with `-`). Each terminal tab is its own cgroup, so all four processes have to be started in that same tab.

Start `min_clones` processes (4). Each allocates `min_group_mb / min_clones` MiB, which is 256. `bytearray` zeroes the allocation, so those pages count in `VmRSS`. Four of them meet `min_group_mb` (1024). The processes then sleep, which keeps them idle (`S`, no CPU ticks between the two samples):

```sh
for _ in 1 2 3 4
do
python3 -c 'b = bytearray(256 * 1024 * 1024); import time; time.sleep(10**9)' &
done
ps -o pid,stat,rss= -p $(jobs -p)
```

Wait until every row shows state `S` and an RSS of at least about 262144 KiB. A process still allocating is not idle, and a scan started before all four exist will miss the group.

From the checkout shell:

```sh
./bin/ramcleaner watch --history-file /tmp/ramcleaner-trial/history.json
```

Click **Hide...** on the notification whose PIDs are the four sleepers, then choose **24 hours**. The dialog is titled ramCleaner, names that finding and its size, and lists **1 hour**, **6 hours**, **24 hours**, and **Until reboot**. Click **Later** on any other notification from this run. **Later** records nothing, so a later timer run asks again. Cancelling the Hide dialog or closing it also records nothing. **Stop** sends `SIGTERM` to the PIDs named on that notification; the trial uses **Stop** only on the next scan, and only for those four PIDs. `watch` holds `watch.lock` until every notification in the run is answered, including the Hide dialog, or until `ask_timeout_minutes` (default 10) elapses. The dialog's timeout is the time still left in that wait.

After that `watch` exits, list the suppression and clear it:

```sh
./bin/ramcleaner ignored --history-file /tmp/ramcleaner-trial/history.json
./bin/ramcleaner ignored --clear --history-file /tmp/ramcleaner-trial/history.json
```

`ignored` prints one `idle-clones:` key and an expiry time. **Until reboot** prints `until reboot` instead of a clock time. `--clear` empties the throwaway `ignored.json`. Clearing while `watch` still holds `watch.lock` prints `another watch is running` and exits `1`.

Run `watch` again. Click **Stop** on the trial notification only. Click **Later** on any other notification.

```sh
./bin/ramcleaner watch --history-file /tmp/ramcleaner-trial/history.json
```

**Stop** does not pass `--force`. The four sleepers should exit. A follow-up notification reports how many processes stopped. In the workload tab, the same PIDs should be gone.

## 3. Two findings, then Details

A second terminal tab starts another four of the same sleepers, so the next scan has two idle-clones findings (each tab is its own cgroup):

```sh
for _ in 1 2 3 4
do
python3 -c 'b = bytearray(256 * 1024 * 1024); import time; time.sleep(10**9)' &
done
ps -o pid,stat,rss= -p $(jobs -p)
```

Wait until every row in that tab shows state `S` and an RSS of at least about 262144 KiB. From the checkout shell:

```sh
./bin/ramcleaner watch --history-file /tmp/ramcleaner-trial/history.json
```

**Details...** on either notification opens one checklist titled ramCleaner listing both findings. Ticking both and confirming stops both, the same way **Stop** does for a single notification. Cancelling the checklist, closing it, or letting it time out stops nothing from it. An other-user warning, when one is pending, appears in the dialog text only and is not a row. A notification whose finding was stopped from the checklist can stay on screen until closed; its buttons do nothing. **Later** on any other notification from this run records nothing.

## 4. What to record when the result differs

When a step does not match this guide, record:

- The finding line printed by `watch`, or the fact that it printed nothing before exiting.
- Whether a notification appeared, which action was clicked, the Hide duration if any, and any `Warning:` line (`notify-send` unavailable or failed, `zenity` unavailable or failed, or `another watch is running`).
- The `ignored` listing before `--clear`.
- After **Stop**: the follow-up text (`stopped=` and `still_alive=`) and whether the four PIDs were still alive.
- When no idle-clones finding appears: state, RSS, and cgroup of the four PIDs, whether they were all started in one tab, and whether the shell running `watch` had `XDG_CONFIG_HOME` pointing at the throwaway config (`min_age_hours = 0`).

## Cleanup

When the four processes are still running, terminate the background jobs in the workload tab:

```sh
kill %1 %2 %3 %4
```

Remove the throwaway directory from the checkout shell:

```sh
rm -rf /tmp/ramcleaner-trial
unset XDG_CONFIG_HOME
```

`unset` drops `XDG_CONFIG_HOME` for this shell, including a value that was set before the trial. Restore a saved value when this shell had one.
