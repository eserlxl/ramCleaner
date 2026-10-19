# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ramcleaner.config import Config
from ramcleaner.detect import Finding, is_protected
from ramcleaner.procscan import Proc, _parse_cmdline, _parse_stat


@dataclass(frozen=True)
class StopResult:
    finding_key: str
    method: str
    stopped: tuple[int, ...]
    still_alive: tuple[int, ...]
    skipped: tuple[tuple[int, str], ...]


def _read_proc(proc_root: Path, pid: int) -> Proc | None:
    entry = proc_root / str(pid)
    try:
        stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        cmdline_raw = (entry / "cmdline").read_bytes()
        pid_num, comm, state, ppid, cpu_ticks, start_ticks = _parse_stat(stat_text)
    except (OSError, ValueError, IndexError):
        return None
    return Proc(
        pid=pid_num,
        ppid=ppid,
        state=state,
        comm=comm,
        cmdline=_parse_cmdline(cmdline_raw),
        uid=0,
        rss_kb=0,
        swap_kb=0,
        cpu_ticks=cpu_ticks,
        start_ticks=start_ticks,
        cgroup="",
    )


def _has_exited(proc_root: Path, pid: int, start_ticks: int) -> bool:
    current = _read_proc(proc_root, pid)
    return (
        current is None
        or current.start_ticks != start_ticks
        or current.state == "Z"
    )


def _wait_for_exit(
    proc_root: Path,
    targets: list[tuple[int, int]],
    timeout: float,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> list[tuple[int, int]]:
    deadline = monotonic() + timeout
    survivors = [item for item in targets if not _has_exited(proc_root, item[0], item[1])]
    while survivors and monotonic() < deadline:
        sleep(0.2)
        survivors = [item for item in survivors if not _has_exited(proc_root, item[0], item[1])]
    return survivors


def _match_stop_rule(targets: list[Proc], config: Config) -> str | None:
    for pattern, command in config.stop_rules:
        if any(re.search(pattern, " ".join(proc.cmdline)) for proc in targets):
            return command
    return None


def stop_finding(
    finding: Finding,
    config: Config,
    *,
    proc_root: str | Path = "/proc",
    force: bool = False,
    pidfd_open: Callable[[int], int] = os.pidfd_open,
    send_signal: Callable[[int, int], Any] = signal.pidfd_send_signal,
    close: Callable[[int], Any] = os.close,
    run: Callable[..., Any] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> StopResult:
    root = Path(proc_root)
    scanned_by_pid = {proc.pid: proc for proc in finding.procs}
    skipped: list[tuple[int, str]] = []
    targets: list[Proc] = []
    pidfds: dict[int, int] = {}

    try:
        for pid in finding.pids:
            # Open the pidfd before reading /proc so the fd pins the process the check verifies.
            try:
                fd = pidfd_open(pid)
            except ProcessLookupError:
                skipped.append((pid, "gone"))
                continue
            except PermissionError:
                skipped.append((pid, "not permitted"))
                continue
            except OSError:
                skipped.append((pid, "pidfd unavailable"))
                continue
            pidfds[pid] = fd

            scanned = scanned_by_pid.get(pid)
            current = _read_proc(root, pid)
            if current is None:
                close(pidfds.pop(pid))
                skipped.append((pid, "gone"))
                continue
            # Without the scanned identity a reused pid cannot be told apart, so never signal it.
            if scanned is None:
                close(pidfds.pop(pid))
                skipped.append((pid, "not in scan"))
                continue
            if (
                current.start_ticks != scanned.start_ticks
                or current.cmdline != scanned.cmdline
            ):
                close(pidfds.pop(pid))
                skipped.append((pid, "pid reused"))
                continue
            if is_protected(current, config) or is_protected(scanned, config):
                close(pidfds.pop(pid))
                skipped.append((pid, "protected"))
                continue
            targets.append(current)

        if not targets:
            return StopResult(
                finding_key=finding.key,
                method="SIGTERM",
                stopped=(),
                still_alive=(),
                skipped=tuple(skipped),
            )

        matched_command = _match_stop_rule(targets, config)
        if matched_command is not None:
            method = f"rule: {matched_command}"
            try:
                run(shlex.split(matched_command), check=False, timeout=60)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                # A missing or hung stop command must not abort the remaining findings.
                method = f"rule failed: {matched_command} ({exc})"
            active = [(proc.pid, proc.start_ticks) for proc in targets]
            survivors = _wait_for_exit(root, active, config.term_timeout, sleep, monotonic)
        else:
            method = "SIGTERM"
            gone_on_kill: set[int] = set()
            denied: set[int] = set()
            for proc in targets:
                try:
                    send_signal(pidfds[proc.pid], signal.SIGTERM)
                except ProcessLookupError:
                    gone_on_kill.add(proc.pid)
                except PermissionError:
                    denied.add(proc.pid)
                    skipped.append((proc.pid, "not permitted"))
            targets = [proc for proc in targets if proc.pid not in denied]
            active = [
                (proc.pid, proc.start_ticks)
                for proc in targets
                if proc.pid not in gone_on_kill
            ]
            survivors = _wait_for_exit(root, active, config.term_timeout, sleep, monotonic)
            if force and survivors:
                method = "SIGTERM+SIGKILL"
                still_active: list[tuple[int, int]] = []
                for pid, start_ticks in survivors:
                    current = _read_proc(root, pid)
                    if current is None or current.state == "Z":
                        continue
                    try:
                        send_signal(pidfds[pid], signal.SIGKILL)
                    except ProcessLookupError:
                        continue
                    still_active.append((pid, start_ticks))
                survivors = _wait_for_exit(root, still_active, 2.0, sleep, monotonic)

        alive_set = {pid for pid, _ in survivors}
        stopped = tuple(proc.pid for proc in targets if proc.pid not in alive_set)
        still_alive = tuple(proc.pid for proc in targets if proc.pid in alive_set)
        return StopResult(
            finding_key=finding.key,
            method=method,
            stopped=stopped,
            still_alive=still_alive,
            skipped=tuple(skipped),
        )
    finally:
        for fd in pidfds.values():
            close(fd)
