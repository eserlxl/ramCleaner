# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ramcleaner report` lists memory by the owning application or systemd unit, then findings for idle clones, unreaped zombies, and growth.
- `ramcleaner clean` stops a finding only after approval in the terminal.
- `ramcleaner watch`, run by the systemd user timer, sends a desktop notification with Stop and Ignore actions for each new finding.
- `ramcleaner ignored` lists findings that watch has suppressed, and can clear that list.
- `stop_rules` run a configured graceful stop command instead of sending a signal.
- Owner attribution follows the cgroup v2 path to the application or unit that owns the process.
- Stopping opens a pidfd and re-checks start time and command line before any signal, so a reused PID is not hit.
