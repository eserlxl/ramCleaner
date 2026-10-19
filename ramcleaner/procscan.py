# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    state: str
    comm: str
    cmdline: tuple[str, ...]
    uid: int
    rss_kb: int
    swap_kb: int
    cpu_ticks: int
    start_ticks: int
    cgroup: str


def _parse_stat(text: str) -> tuple[int, str, str, int, int, int]:
    # comm may contain spaces or parentheses, so split on first '(' and last ')'.
    lparen = text.index("(")
    rparen = text.rindex(")")
    pid = int(text[:lparen].strip())
    comm = text[lparen + 1 : rparen]
    rest = text[rparen + 1 :].split()
    state = rest[0]
    ppid = int(rest[1])
    cpu_ticks = int(rest[11]) + int(rest[12])
    start_ticks = int(rest[19])
    return pid, comm, state, ppid, cpu_ticks, start_ticks


def _parse_status(text: str) -> tuple[int | None, int, int]:
    uid: int | None = None
    rss_kb = 0
    swap_kb = 0
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                uid = int(parts[1])
        elif line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2:
                rss_kb = int(parts[1])
        elif line.startswith("VmSwap:"):
            parts = line.split()
            if len(parts) >= 2:
                swap_kb = int(parts[1])
    return uid, rss_kb, swap_kb


def _parse_cmdline(raw: bytes) -> tuple[str, ...]:
    if not raw:
        return ()
    parts = raw.decode("utf-8", errors="replace").split("\x00")
    if parts and parts[-1] == "":
        parts.pop()
    return tuple(parts)


def _parse_cgroup(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return ""


def scan_processes(
    proc_root: str | Path = "/proc",
    uid: int | None = None,
) -> dict[int, Proc]:
    target_uid = os.getuid() if uid is None else uid
    root = Path(proc_root)
    procs: dict[int, Proc] = {}
    try:
        entries = list(root.iterdir())
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return procs

    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            status_text = (entry / "status").read_text(encoding="utf-8", errors="replace")
            cmdline_raw = (entry / "cmdline").read_bytes()
            cgroup_text = (entry / "cgroup").read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue

        try:
            pid, comm, state, ppid, cpu_ticks, start_ticks = _parse_stat(stat_text)
            real_uid, rss_kb, swap_kb = _parse_status(status_text)
        except (ValueError, IndexError):
            continue

        if real_uid is None or real_uid != target_uid:
            continue

        procs[pid] = Proc(
            pid=pid,
            ppid=ppid,
            state=state,
            comm=comm,
            cmdline=_parse_cmdline(cmdline_raw),
            uid=real_uid,
            rss_kb=rss_kb,
            swap_kb=swap_kb,
            cpu_ticks=cpu_ticks,
            start_ticks=start_ticks,
            cgroup=_parse_cgroup(cgroup_text),
        )
    return procs


def read_cgroup_memory(
    cgroup_root: str | Path,
    cgroup_path: str,
) -> tuple[int, int, int] | None:
    rel = cgroup_path.strip("/")
    if not rel:
        return None
    cg_dir = Path(cgroup_root) / rel
    try:
        stats = (cg_dir / "memory.stat").read_text(encoding="utf-8").splitlines()
        anon = next(int(line.split()[1]) for line in stats if line.split()[:1] == ["anon"])
        swap = int((cg_dir / "memory.swap.current").read_text(encoding="utf-8").strip())
        try:
            zswap = int((cg_dir / "memory.zswap.current").read_text(encoding="utf-8").strip())
        except FileNotFoundError:
            zswap = 0
    except (OSError, ValueError, IndexError, StopIteration):
        return None
    return anon, swap, zswap


def read_uptime(proc_root: str | Path) -> float:
    return float((Path(proc_root) / "uptime").read_text(encoding="utf-8").split()[0])


def clock_ticks() -> int:
    return os.sysconf("SC_CLK_TCK")
