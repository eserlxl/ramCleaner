# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fcntl
import json
import math
import pwd
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from ramcleaner.actions import StopResult, stop_finding
from ramcleaner.config import Config
from ramcleaner.detect import Finding, detect, format_size
from ramcleaner.history import append_scan, load_history, write_json_atomic
from ramcleaner.owner import resolve_owner
from ramcleaner.procscan import (
    Proc,
    clock_ticks,
    read_boot_id,
    read_uptime,
    scan_processes,
)


def format_finding(finding: Finding) -> str:
    return (
        f"{finding.rule}  {finding.owner_label}  {len(finding.pids)} pids  "
        f"{format_size(finding.rss_kb)} RAM  {format_size(finding.swap_kb)} swap  "
        f"{finding.reason}"
    )


def format_stop_result(result: StopResult) -> str:
    count = len(result.stopped)
    noun = "process" if count == 1 else "processes"
    stopped = ", ".join(str(pid) for pid in result.stopped)
    parts = [f"{count} {noun} stopped: {stopped}." if stopped else f"{count} {noun} stopped."]
    parts.append(f"Method: {result.method}.")
    if result.still_alive:
        alive = ", ".join(str(pid) for pid in result.still_alive)
        parts.append(f"Still running: {alive}.")
    if result.skipped:
        skipped = ", ".join(f"{pid} ({reason})" for pid, reason in result.skipped)
        parts.append(f"Skipped: {skipped}.")
    return " ".join(parts)


def _expiry(val: object) -> float | None:
    if type(val) in (int, float) and math.isfinite(val):
        return float(val)
    return None


def _boot_id_value(val: object) -> str | None:
    if isinstance(val, dict) and set(val) == {"boot_id"} and isinstance(val["boot_id"], str):
        return val["boot_id"]
    return None


def _valid_ignored(data: object) -> bool:
    return isinstance(data, dict) and all(
        isinstance(key, str) and (_expiry(val) is not None or _boot_id_value(val) is not None)
        for key, val in data.items()
    )


def _active(val: float | dict[str, str], now: float, boot_id: str | None) -> bool:
    if isinstance(val, dict):
        return val["boot_id"] == boot_id
    return val > now


def load_ignored(path: str | Path) -> dict[str, float | dict[str, str]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not _valid_ignored(data):
            raise ValueError("invalid ignored entries")
        loaded: dict[str, float | dict[str, str]] = {}
        for key, val in data.items():
            boot_id = _boot_id_value(val)
            if boot_id is not None:
                loaded[key] = {"boot_id": boot_id}
            else:
                loaded[key] = float(val)
        return loaded
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, OverflowError) as exc:
        print(f"Warning: cannot read ignored {path}: {exc}", file=sys.stderr)
        return {}


def save_ignored(
    path: str | Path,
    ignored: dict[str, float | dict[str, str]],
    now: float,
    boot_id: str | None = None,
) -> None:
    active = {key: val for key, val in ignored.items() if _active(val, now, boot_id)}
    write_json_atomic(path, active)


_HIDE_HOURS = {"1 hour": 1, "6 hours": 6, "24 hours": 24}


def _user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class OtherUserGroup(NamedTuple):
    owner_cg: str
    label: str
    names: str
    members: tuple[Proc, ...]

    @property
    def total_kb(self) -> int:
        return sum(proc.rss_kb + proc.swap_kb for proc in self.members)


def other_user_groups(procs: dict[int, Proc], min_mb: int) -> list[OtherUserGroup]:
    grouped: dict[str, list[Proc]] = {}
    labels: dict[str, str] = {}
    for proc in procs.values():
        owner, owner_cg = resolve_owner(proc.cgroup)
        grouped.setdefault(owner_cg, []).append(proc)
        labels[owner_cg] = owner.label
    groups: list[OtherUserGroup] = []
    for owner_cg, members in grouped.items():
        uids = sorted({proc.uid for proc in members})
        group = OtherUserGroup(
            owner_cg=owner_cg,
            label=labels[owner_cg],
            names=", ".join(_user_name(uid) for uid in uids),
            members=tuple(sorted(members, key=lambda proc: proc.pid)),
        )
        if group.total_kb >= min_mb * 1024:
            groups.append(group)
    groups.sort(key=lambda group: (-group.total_kb, group.owner_cg))
    return groups


def _other_user_warnings(procs: dict[int, Proc], min_mb: int) -> list[Finding]:
    return [
        Finding(
            key=f"other-user:{group.owner_cg}",
            rule="other-user",
            owner_label=group.label,
            pids=tuple(proc.pid for proc in group.members),
            rss_kb=sum(proc.rss_kb for proc in group.members),
            swap_kb=sum(proc.swap_kb for proc in group.members),
            reason=f"held by {group.names}; information only, not stopped",
            procs=group.members,
        )
        for group in other_user_groups(procs, min_mb)
    ]


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
        if config.other_users_notify:
            procs, others = scan_processes(
                proc_root=args_like.proc_root,
                all_users=True,
            )
        else:
            procs = scan_processes(proc_root=args_like.proc_root)
            others = {}
        stamp = float(now())
        boot_id = read_boot_id(args_like.proc_root)

        findings = detect(
            first,
            procs,
            config,
            read_uptime(args_like.proc_root),
            clock_ticks(),
            history,
            now=stamp,
            boot_id=boot_id,
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
        if boot_id is not None:
            entry["boot_id"] = boot_id
        append_scan(history_path, entry, keep_hours=config.history_hours, now=stamp)

        ignored_path = state_dir / "ignored.json"
        ignored = load_ignored(ignored_path)
        has_expired = any(not _active(val, stamp, boot_id) for val in ignored.values())
        unsuppressed = [
            finding
            for finding in findings
            if not _active(ignored.get(finding.key, 0.0), stamp, boot_id)
        ]
        warnings = [
            warning
            for warning in _other_user_warnings(others, config.other_users_min_mb)
            if not _active(ignored.get(warning.key, 0.0), stamp, boot_id)
        ]
        pending = [*unsuppressed, *warnings]

        if not pending:
            if has_expired:
                save_ignored(ignored_path, ignored, stamp, boot_id)
            return 0

        for finding in pending:
            print(format_finding(finding))

        answers = notifier.ask(pending, config.ask_timeout_minutes * 60)
        exit_code = 0
        suppressed_any = False

        for finding in pending:
            answer = answers.get(finding.key, "")
            if answer == "stop":
                # Information warnings have no Stop action and must not be stopped or hidden.
                if finding.rule == "other-user":
                    continue
                result = stopper(finding, config, proc_root=args_like.proc_root)
                summary = (
                    f"{finding.owner_label}: stopped {len(result.stopped)} processes"
                )
                notifier.inform(summary, format_stop_result(result))
                if result.still_alive:
                    exit_code = 1
            elif answer == "later":
                print(f"{finding.owner_label}: later, will ask again")
            elif answer == "timeout":
                print(f"{finding.owner_label}: no answer, will ask again")
            elif answer == "unavailable":
                print(f"{finding.owner_label}: notification unavailable, will ask again")
            elif answer == "cancel":
                print(f"{finding.owner_label}: hide cancelled, will ask again")
            elif answer == "Until reboot":
                if boot_id is None:
                    print(f"{finding.owner_label}: no boot id, will ask again")
                else:
                    ignored[finding.key] = {"boot_id": boot_id}
                    suppressed_any = True
            elif answer in _HIDE_HOURS:
                ignored[finding.key] = stamp + _HIDE_HOURS[answer] * 3600
                suppressed_any = True
            else:
                # Dismissal, a missing or failed zenity, or any other answer.
                ignored[finding.key] = stamp + config.ignore_for_hours * 3600
                suppressed_any = True

        if suppressed_any or has_expired:
            save_ignored(ignored_path, ignored, stamp, boot_id)

        return exit_code
