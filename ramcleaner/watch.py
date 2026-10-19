# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fcntl
import json
import math
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ramcleaner.actions import StopResult, stop_finding
from ramcleaner.config import Config
from ramcleaner.detect import Finding, detect
from ramcleaner.history import append_scan, load_history, write_json_atomic
from ramcleaner.procscan import clock_ticks, read_uptime, scan_processes


def format_finding(finding: Finding) -> str:
    return (
        f"{finding.rule}  {finding.owner_label}  {len(finding.pids)} pids  "
        f"{finding.rss_kb / 1024:.1f} MB RAM  {finding.swap_kb / 1024:.1f} MB swap  "
        f"{finding.reason}"
    )


def format_stop_result(result: StopResult) -> str:
    stopped = ", ".join(str(pid) for pid in result.stopped) or "none"
    alive = ", ".join(str(pid) for pid in result.still_alive) or "none"
    skipped = (
        ", ".join(f"{pid} ({reason})" for pid, reason in result.skipped) or "none"
    )
    return (
        f"method={result.method}  stopped={stopped}  "
        f"still_alive={alive}  skipped={skipped}"
    )


def _valid_ignored(data: object) -> bool:
    return isinstance(data, dict) and all(
        isinstance(key, str) and type(val) in (int, float) and math.isfinite(val)
        for key, val in data.items()
    )


def load_ignored(path: str | Path) -> dict[str, float]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not _valid_ignored(data):
            raise ValueError("invalid ignored entries")
        return {key: float(val) for key, val in data.items()}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, OverflowError) as exc:
        print(f"Warning: cannot read ignored {path}: {exc}", file=sys.stderr)
        return {}


def save_ignored(path: str | Path, ignored: dict[str, float], now: float) -> None:
    active = {key: until for key, until in ignored.items() if until > now}
    write_json_atomic(path, active)


def run_watch(
    args_like: Any,
    config: Config,
    *,
    notifier: Any,
    stopper: Callable[..., StopResult] = stop_finding,
    now: Callable[[], float] = time.time,
) -> int:
    history_path = Path(args_like.history_file)
    state_dir = history_path.parent
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "watch.lock"

    with lock_path.open("a", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("another watch is running", file=sys.stderr)
            return 0

        history = load_history(history_path)
        first = scan_processes(proc_root=args_like.proc_root)
        time.sleep(args_like.interval)
        procs = scan_processes(proc_root=args_like.proc_root)
        stamp = float(now())

        findings = detect(
            first,
            procs,
            config,
            read_uptime(args_like.proc_root),
            clock_ticks(),
            history,
            args_like.cgroup_root,
            now=stamp,
        )

        entry = {
            "time": stamp,
            "procs": {
                f"{proc.pid}:{proc.start_ticks}": proc.rss_kb + proc.swap_kb
                for proc in procs.values()
            },
            "zombies": sorted(
                f"{proc.pid}:{proc.start_ticks}"
                for proc in procs.values()
                if proc.state == "Z"
            ),
        }
        append_scan(history_path, entry, keep_hours=config.history_hours, now=stamp)

        ignored_path = state_dir / "ignored.json"
        ignored = load_ignored(ignored_path)
        has_expired = any(until <= stamp for until in ignored.values())
        unsuppressed = [
            finding for finding in findings if ignored.get(finding.key, 0.0) <= stamp
        ]

        if not unsuppressed:
            if has_expired:
                save_ignored(ignored_path, ignored, stamp)
            return 0

        for finding in unsuppressed:
            print(format_finding(finding))

        answers = notifier.ask(unsuppressed)
        exit_code = 0
        suppressed_any = False

        for finding in unsuppressed:
            answer = answers.get(finding.key, "")
            if answer == "stop":
                result = stopper(finding, config, proc_root=args_like.proc_root)
                summary = (
                    f"{finding.owner_label}: stopped {len(result.stopped)} processes"
                )
                notifier.inform(summary, format_stop_result(result))
                if result.still_alive:
                    exit_code = 1
            else:
                ignored[finding.key] = stamp + config.ignore_for_hours * 3600
                suppressed_any = True

        if suppressed_any or has_expired:
            save_ignored(ignored_path, ignored, stamp)

        return exit_code
