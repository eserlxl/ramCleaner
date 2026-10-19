# Installation

## Requirements

- Linux >= 5.3 (pidfd) with `/proc` and cgroup v2 mounted at `/sys/fs/cgroup`.
- Python 3.11 or newer. Only the Python standard library is used.
- `notify-send` from `libnotify` (`libnotify-bin` on Debian/Ubuntu, `libnotify` on Fedora/Arch) with `--action` support when running `ramcleaner watch`.
- `zenity` (optional) for the **Hide...** duration menu in `ramcleaner watch`. Without it, **Hide...** suppresses the finding for `ignore_for_hours` and prints one `Warning:` line.
- `systemd` user manager when scheduling periodic runs with `ramcleaner-watch.timer`.

## Install with `make`

Install into your home directory (no root privileges required):

```sh
make install PREFIX=~/.local
```

Ensure `~/.local/bin` is on your `PATH`.

Install system-wide:

```sh
sudo make install PREFIX=/usr/local
```

### Make variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PREFIX` | `/usr/local` | Base installation prefix. |
| `BINDIR` | `$(PREFIX)/bin` | Directory for the `ramcleaner` executable. |
| `LIBDIR` | `$(PREFIX)/lib/ramcleaner` | Directory for the Python package (`ramcleaner/*.py`). Must resolve to `$(BINDIR)/../lib/ramcleaner` so the launcher finds the package relative to its own path. |
| `USERUNITDIR` | `$(PREFIX)/share/systemd/user` when `PREFIX` is `~/.local`, else `$(PREFIX)/lib/systemd/user` | Directory for `ramcleaner-watch.service` and `ramcleaner-watch.timer`. |
| `DESTDIR` | *(empty)* | Staging root prepended to every destination path during packaging. |

### Make targets

| Target | Action |
| --- | --- |
| `install` | Copies `ramcleaner/*.py` to `$(DESTDIR)$(LIBDIR)/ramcleaner/` (mode `644`), `bin/ramcleaner` to `$(DESTDIR)$(BINDIR)/ramcleaner` (mode `755`), `config.example.toml` to `$(DESTDIR)$(PREFIX)/share/ramcleaner/config.example.toml` (mode `644`), and the two systemd user units to `$(DESTDIR)$(USERUNITDIR)/` (mode `644`) with `@BINDIR@` replaced by `$(BINDIR)`. |
| `uninstall` | Removes the installed executable, package files, example config, and systemd user units, then removes empty `LIBDIR` and `$(PREFIX)/share/ramcleaner` directories. |
| `test` | Runs `python3 -B -m unittest discover -s tests`. |
| `lint` | Runs `ruff check --target-version py311 ramcleaner tests bin/ramcleaner`, which also rejects syntax newer than Python 3.11. |

## Arch Linux package

The repository ships a `PKGBUILD` for a `ramcleaner` package that installs into `/usr` (the user units go to `/usr/lib/systemd/user`). It is not on the AUR yet; [packaging.md](packaging.md) shows how to build it locally. The package does not enable the timer: each user enables it as shown below.

## Run from a checkout

You can run ramCleaner directly from the repository without installing:

```sh
./bin/ramcleaner report
```

or:

```sh
python3 -m ramcleaner report
```

A hands-on trial of `report`, `clean`, and the notification **Stop**, **Later**, and **Hide...** actions, using a throwaway history file so the default state directory stays untouched, is in [trial.md](trial.md).

## Enable and disable the systemd user timer

After installing with the default `USERUNITDIR`, systemd finds the units:

```sh
systemctl --user daemon-reload
systemctl --user enable --now ramcleaner-watch.timer
```

`ramcleaner-watch.timer` runs `ramcleaner-watch.service` 10 minutes after boot (`OnBootSec=10min`) and then every 15 minutes (`OnUnitActiveSec=15min`); while a run still waits for a notification answer, the timer starts no second run. `ramcleaner-watch.service` uses `Type=oneshot` and `TimeoutStartSec=infinity` while `ramcleaner watch` bounds its notification wait to `ask_timeout_minutes` (default `10` minutes). Keep `ask_timeout_minutes` below the 15-minute timer interval so unanswered notifications finish before the next scheduled scan and history recording continues on every tick.

Check the timer schedule and last service run:

```sh
systemctl --user status ramcleaner-watch.timer
systemctl --user status ramcleaner-watch.service
```

Disable and stop the timer:

```sh
systemctl --user disable --now ramcleaner-watch.timer
```

## Uninstall

If the user timer is enabled, disable it first, then run `make uninstall` with the same `PREFIX` used for installation:

```sh
systemctl --user disable --now ramcleaner-watch.timer
make uninstall PREFIX=~/.local
systemctl --user daemon-reload
```

`make uninstall` does not delete user configuration (`$XDG_CONFIG_HOME/ramcleaner/config.toml`) or state files (`$XDG_STATE_HOME/ramcleaner/`). Remove those directories manually if you no longer want them.
