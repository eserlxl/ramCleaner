# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from ramcleaner.config import Config
from ramcleaner.owner import resolve_owner
from ramcleaner.procscan import Proc


@dataclass(frozen=True)
class Finding:
    key: str
    rule: str
    owner_label: str
    pids: tuple[int, ...]
    rss_kb: int
    swap_kb: int
    reason: str


def command_key(proc: Proc) -> tuple[str, str]:
    executable = os.path.basename(proc.cmdline[0] if proc.cmdline else proc.comm)
    argument = next((arg for arg in proc.cmdline[1:] if not arg.startswith("-")), "")
    return executable, argument


def _is_browser_child(proc: Proc) -> bool:
    # Chromium and Electron run one idle renderer per background tab or window; they look
    # like clones, but stopping one closes a tab the user still has open.
    return any(arg.startswith("--type=") for arg in proc.cmdline[1:])


def detect(
    first: dict[int, Proc],
    second: dict[int, Proc],
    config: Config,
    uptime_s: float,
    clk_tck: int,
    history: list[dict],
    cgroup_root: str | Path,
) -> list[Finding]:
    protected_pids = {1, os.getpid(), os.getppid()}
    protected_names = {"systemd", "kwin_wayland", "plasmashell", "ksmserver", *config.protected}
    eligible = {
        pid: proc for pid, proc in second.items()
        if pid not in protected_pids and proc.comm not in protected_names
    }
    findings: list[Finding] = []
    clones: dict[tuple[str, tuple[str, str]], list[Proc]] = {}
    for proc in eligible.values():
        previous = first.get(proc.pid)
        if (
            previous is not None
            and previous.start_ticks == proc.start_ticks
            and previous.cpu_ticks == proc.cpu_ticks
            and previous.state in ("S", "I")
            and proc.state in ("S", "I")
            and uptime_s - proc.start_ticks / clk_tck > config.min_age_hours * 3600
            and not _is_browser_child(proc)
        ):
            _, owner_cgroup = resolve_owner(proc.cgroup)
            clones.setdefault((owner_cgroup, command_key(proc)), []).append(proc)

    for (owner_cgroup, command), members in clones.items():
        rss = sum(proc.rss_kb for proc in members)
        swap = sum(proc.swap_kb for proc in members)
        if len(members) >= config.min_clones and rss + swap >= config.min_group_mb * 1024:
            owner, _ = resolve_owner(owner_cgroup)
            findings.append(Finding(
                key=f"idle-clones:{owner_cgroup}:{command}",
                rule="idle-clones",
                owner_label=owner.label,
                pids=tuple(sorted(proc.pid for proc in members)),
                rss_kb=rss,
                swap_kb=swap,
                reason=f"{len(members)} idle copies of {' '.join(command).strip()} "
                       f"older than {config.min_age_hours} h",
            ))

    previous_zombies = set(history[-1]["zombies"]) if history else set()
    zombies: dict[int, list[int]] = {}
    for proc in eligible.values():
        parent = eligible.get(proc.ppid)
        if (
            proc.state == "Z"
            and f"{proc.pid}:{proc.start_ticks}" in previous_zombies
            and parent is not None
            and parent.state not in ("Z", "X", "x")
        ):
            zombies.setdefault(parent.pid, []).append(proc.pid)
    for parent_pid, children in zombies.items():
        parent = eligible[parent_pid]
        owner, _ = resolve_owner(parent.cgroup)
        findings.append(Finding(
            key=f"zombie:{parent.pid}:{parent.start_ticks}",
            rule="zombie",
            owner_label=owner.label,
            pids=(parent.pid,),
            rss_kb=parent.rss_kb,
            swap_kb=parent.swap_kb,
            reason=f"Parent {parent.pid} ({parent.comm}) does not reap zombies "
                   + ", ".join(str(pid) for pid in sorted(children)),
        ))

    now = time.time()
    recent = sorted(
        (entry for entry in history if now - config.history_hours * 3600 <= entry["time"] <= now),
        key=lambda entry: entry["time"],
    )
    for proc in eligible.values():
        identity = f"{proc.pid}:{proc.start_ticks}"
        sizes = [entry["procs"][identity] for entry in recent if identity in entry["procs"]]
        sizes.append(proc.rss_kb + proc.swap_kb)
        if (
            len(sizes) >= 5
            and all(after > before for before, after in pairwise(sizes))
            and sizes[-1] - sizes[0] >= config.min_growth_mb * 1024
        ):
            owner, _ = resolve_owner(proc.cgroup)
            findings.append(Finding(
                key=f"growth:{identity}",
                rule="growth",
                owner_label=owner.label,
                pids=(proc.pid,),
                rss_kb=proc.rss_kb,
                swap_kb=proc.swap_kb,
                reason=f"RSS + swap grew by {(sizes[-1] - sizes[0]) / 1024:.1f} MB "
                       f"across {len(sizes)} scans",
            ))

    return sorted(findings, key=lambda finding: -(finding.rss_kb + finding.swap_kb))
