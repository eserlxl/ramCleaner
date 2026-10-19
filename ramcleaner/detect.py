# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from itertools import pairwise

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
    procs: tuple[Proc, ...] = ()


_PROTECTED_COMMS = frozenset({"systemd", "kwin_wayland", "plasmashell", "ksmserver"})


def is_protected(proc: Proc, config: Config) -> bool:
    return (
        proc.pid in (1, os.getpid(), os.getppid())
        or proc.comm in _PROTECTED_COMMS
        or proc.comm in config.protected
    )


def command_key(proc: Proc) -> tuple[str, str]:
    executable = os.path.basename(proc.cmdline[0] if proc.cmdline else proc.comm)
    argument = next((arg for arg in proc.cmdline[1:] if not arg.startswith("-")), "")
    return executable, argument


def _is_browser_child(proc: Proc) -> bool:
    # Chromium and Electron (--type=) and Firefox (-contentproc) run one content process per
    # background tab or window; they look like clones, but stopping one closes a tab.
    return any(arg.startswith("--type=") or arg == "-contentproc" for arg in proc.cmdline[1:])


def same_boot_history(history: list[dict], boot_id: str | None) -> list[dict]:
    # Entries from another boot, or recorded before boot_id existed, must not supply samples.
    if boot_id is None:
        return history
    return [entry for entry in history if entry.get("boot_id") == boot_id]


def detect(
    first: dict[int, Proc],
    second: dict[int, Proc],
    config: Config,
    uptime_s: float,
    clk_tck: int,
    history: list[dict],
    now: float | None = None,
    boot_id: str | None = None,
) -> list[Finding]:
    eligible = {
        pid: proc for pid, proc in second.items()
        if not is_protected(proc, config)
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
            ordered = tuple(sorted(members, key=lambda proc: proc.pid))
            findings.append(Finding(
                key=f"idle-clones:{owner_cgroup}:{command}",
                rule="idle-clones",
                owner_label=owner.label,
                pids=tuple(proc.pid for proc in ordered),
                rss_kb=rss,
                swap_kb=swap,
                reason=f"{len(members)} idle copies of {' '.join(command).strip()} "
                       f"older than {config.min_age_hours} h",
                procs=ordered,
            ))

    usable = same_boot_history(history, boot_id)
    previous_zombies = set(usable[-1]["zombies"]) if usable else set()
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
        # start_ticks counts from boot, so a known boot_id keeps the suppression on that boot.
        if boot_id is None:
            zombie_key = f"zombie:{parent.pid}:{parent.start_ticks}"
        else:
            zombie_key = f"zombie:{boot_id}:{parent.pid}:{parent.start_ticks}"
        findings.append(Finding(
            key=zombie_key,
            rule="zombie",
            owner_label=owner.label,
            pids=(parent.pid,),
            rss_kb=parent.rss_kb,
            swap_kb=parent.swap_kb,
            reason=f"Parent {parent.pid} ({parent.comm}) does not reap zombies "
                   + ", ".join(str(pid) for pid in sorted(children)),
            procs=(parent,),
        ))

    if now is None:
        now = time.time()
    recent = sorted(
        (entry for entry in usable if now - config.history_hours * 3600 <= entry["time"] <= now),
        key=lambda entry: entry["time"],
    )
    for proc in eligible.values():
        identity = f"{proc.pid}:{proc.start_ticks}"
        sizes = [entry["procs"][identity] for entry in recent if identity in entry["procs"]]
        sizes.append(proc.rss_kb + proc.swap_kb)
        if (
            len(sizes) >= 5
            and all(after * 100 >= before * 99 for before, after in pairwise(sizes))
            and sizes[-1] - sizes[0] >= config.min_growth_mb * 1024
            and not _is_browser_child(proc)
        ):
            owner, _ = resolve_owner(proc.cgroup)
            if boot_id is None:
                growth_key = f"growth:{identity}"
            else:
                growth_key = f"growth:{boot_id}:{identity}"
            findings.append(Finding(
                key=growth_key,
                rule="growth",
                owner_label=owner.label,
                pids=(proc.pid,),
                rss_kb=proc.rss_kb,
                swap_kb=proc.swap_kb,
                reason=f"RSS + swap grew by {(sizes[-1] - sizes[0]) / 1024:.1f} MB "
                       f"across {len(sizes)} scans",
                procs=(proc,),
            ))

    return sorted(findings, key=lambda finding: -(finding.rss_kb + finding.swap_kb))
