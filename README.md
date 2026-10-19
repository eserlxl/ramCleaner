# ramCleaner

[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)

ramCleaner finds processes that hold memory they no longer use (idle helper copies a daemon forgot to close, zombies nobody reaps, processes that only grow), attributes them to the application or systemd unit that really owns them, and stops them only after you approve. It never stops anything on its own.

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [Workflow](#workflow)
- [Safety](#safety)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)

## Quick start

```sh
make install PREFIX=~/.local
ramcleaner report
```

## Install

Requires Linux with cgroup v2, Python 3.11+, and `notify-send` (from `libnotify`) for desktop notifications. `zenity` is optional and supplies the Hide duration menu. Install into `~/.local` with `make install PREFIX=~/.local` or system-wide with `sudo make install PREFIX=/usr/local`.

See [docs/installation.md](docs/installation.md) for `make` variables, systemd timer setup, and uninstall steps.

## Workflow

Inspect memory by owning application or unit and review any detected findings:

```sh
ramcleaner report
```

Interactively review and stop findings from a terminal:

```sh
ramcleaner clean
```

Or run `ramcleaner watch` periodically from the systemd user timer to receive desktop notifications with **Stop**, **Later**, and **Hide...** buttons:

```sh
systemctl --user daemon-reload
systemctl --user enable --now ramcleaner-watch.timer
```

## Safety

- Nothing is stopped without your approval (`y`/`yes` in `ramcleaner clean`, or clicking **Stop** on a `ramcleaner watch` notification).
- Before sending any signal, a pidfd is opened for each PID and its `/proc/PID` entry is re-checked to confirm its `start_ticks` and `cmdline` still match the scan and that it is not in the protected list (`PID 1`, `ramcleaner`, `systemd`, `kwin_wayland`, `plasmashell`, `ksmserver`, plus `protected` in `config.toml`); signals are sent through that pidfd so a reused PID can never be hit.
- `SIGTERM` is sent by default; `SIGKILL` is never sent unless `--force` is passed to `ramcleaner clean`.
- Configured `stop_rules` run the configured graceful stop command (split with `shlex.split`, without a shell) instead of sending signals directly.
- Other users' processes are only reported and are never stopped.

## Documentation

### User guides

| Document | Description |
| --- | --- |
| [docs/installation.md](docs/installation.md) | Requirements, `make` variables and targets, systemd user timer setup, and uninstall. |
| [docs/trial.md](docs/trial.md) | Desktop trial of report, clean, and notification Stop, Later, and Hide from a checkout, without the default state directory. |
| [docs/configuration.md](docs/configuration.md) | `config.toml` path, all configuration keys, types, defaults, and `stop_rules` examples. |
| [docs/cli-reference.md](docs/cli-reference.md) | Subcommands, options, state files (`history.json`, `ignored.json`, `watch.lock`), and exit statuses. |

### Maintainer docs

| Path | Description |
| --- | --- |
| [docs/design.md](docs/design.md) | Architecture, `/proc` and cgroup v2 data sources, owner attribution, detection rules, and stopping logic. |
| [docs/packaging.md](docs/packaging.md) | Arch `PKGBUILD` for the `ramcleaner` AUR package (not published yet), test build, and the release and publish steps. |
| [CHANGELOG.md](CHANGELOG.md) | Release notes in Keep a Changelog form; the `[Unreleased]` section is renamed when a version is tagged. |
| [Makefile](Makefile) | Build, install, uninstall, test, and lint targets. |
| [tests/](tests/) | Unit and fixture tests (`tests/fakeproc.py` builds synthetic `/proc` and cgroup trees). |

## Development

Run the linter and unit test suite:

```sh
make lint
make test
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
