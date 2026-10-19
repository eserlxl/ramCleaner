# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


def build_tree(
    root: str | Path,
    procs: Iterable[Mapping[str, Any]],
    cgroups: Mapping[str, tuple[int, int]] | None = None,
) -> tuple[Path, Path]:
    base = Path(root)
    proc_root = base / "proc"
    cgroup_root = base / "cgroup"
    proc_root.mkdir(parents=True, exist_ok=True)
    cgroup_root.mkdir(parents=True, exist_ok=True)

    default_uid = os.getuid()
    for spec in procs:
        pid = int(spec["pid"])
        ppid = int(spec.get("ppid", 1))
        state = str(spec.get("state", "S"))
        comm = str(spec.get("comm", f"proc-{pid}"))
        cmdline = tuple(spec.get("cmdline", ()))
        uid = int(spec.get("uid", default_uid))
        rss_kb = spec.get("rss_kb", 0)
        swap_kb = spec.get("swap_kb", 0)
        if "cpu_ticks" in spec:
            utime = int(spec["cpu_ticks"])
            stime = 0
        else:
            utime = int(spec.get("utime", 0))
            stime = int(spec.get("stime", 0))
        start_ticks = int(spec.get("start_ticks", 100))
        cgroup = str(spec.get("cgroup", "/user.slice/user-1000.slice/session-1.scope"))

        pid_dir = proc_root / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)

        # Fields after ')': [0]=state, [1]=ppid, [2..10]=9 zeros, [11]=utime, [12]=stime,
        # [13..18]=6 zeros, [19]=starttime (field 22).
        tail_fields = [
            state,
            str(ppid),
            *(["0"] * 9),
            str(utime),
            str(stime),
            *(["0"] * 6),
            str(start_ticks),
            *(["0"] * 30),
        ]
        stat_line = f"{pid} ({comm}) " + " ".join(tail_fields) + "\n"
        (pid_dir / "stat").write_text(stat_line, encoding="utf-8")

        if not spec.get("omit_status", False):
            status_lines = [
                f"Name:\t{comm}",
                f"State:\t{state}",
                f"Pid:\t{pid}",
                f"PPid:\t{ppid}",
                f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}",
            ]
            if rss_kb is not None:
                status_lines.append(f"VmRSS:\t{int(rss_kb)} kB")
            if swap_kb is not None:
                status_lines.append(f"VmSwap:\t{int(swap_kb)} kB")
            (pid_dir / "status").write_text("\n".join(status_lines) + "\n", encoding="utf-8")

        raw_cmd = ("\x00".join(cmdline) + "\x00").encode("utf-8") if cmdline else b""
        (pid_dir / "cmdline").write_bytes(raw_cmd)
        (pid_dir / "cgroup").write_text(f"0::{cgroup}\n", encoding="utf-8")

    for cg_path, (cur_bytes, swap_bytes) in (cgroups or {}).items():
        cg_dir = cgroup_root / cg_path.lstrip("/")
        cg_dir.mkdir(parents=True, exist_ok=True)
        (cg_dir / "memory.current").write_text(f"{cur_bytes}\n", encoding="utf-8")
        (cg_dir / "memory.swap.current").write_text(f"{swap_bytes}\n", encoding="utf-8")

    return proc_root, cgroup_root
