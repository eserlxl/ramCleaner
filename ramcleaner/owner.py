# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from ramcleaner.procscan import Proc, read_cgroup_memory

_APP_SCOPE_RE = re.compile(r"^app-(.+)-([^-]+)\.scope$")
_APP_SERVICE_RE = re.compile(r"^app-(.+)@([^@]*)\.service$")
_TAB_SCOPE_RE = re.compile(r"^tab\(([^)]+)\)\.scope$")


@dataclass(frozen=True)
class Owner:
    app: str | None = None
    unit: str | None = None
    tab: str | None = None

    @property
    def label(self) -> str:
        if self.app is not None:
            if self.tab is not None:
                return f"{self.app} tab {self.tab}"
            return self.app
        return self.unit or ""


@dataclass(frozen=True)
class OwnerUsage:
    owner: Owner
    cgroup: str
    rss_kb: int
    swap_kb: int
    cgroup_bytes: int | None
    cgroup_swap_bytes: int | None
    held_by: Proc

    @property
    def cgroup_path(self) -> str:
        return self.cgroup

    @property
    def ram_bytes(self) -> int:
        if self.cgroup_bytes is not None:
            return self.cgroup_bytes
        return self.rss_kb * 1024

    @property
    def swap_bytes(self) -> int:
        if self.cgroup_swap_bytes is not None:
            return self.cgroup_swap_bytes
        return self.swap_kb * 1024

    @property
    def total_bytes(self) -> int:
        return self.ram_bytes + self.swap_bytes


def _decode_escaped(name: str) -> str:
    return name.replace(r"\x2d", "-")


def _match_app_component(part: str) -> str | None:
    m = _APP_SCOPE_RE.match(part) or _APP_SERVICE_RE.match(part)
    if m is None:
        return None
    return _decode_escaped(m.group(1))


def resolve_owner(cgroup_path: str) -> tuple[Owner, str]:
    parts = [p for p in cgroup_path.split("/") if p]
    if not parts:
        return Owner(app=None, unit="/", tab=None), "/"

    app_idx: int | None = None
    app_name: str | None = None
    for idx, part in enumerate(parts):
        matched = _match_app_component(part)
        if matched is not None:
            app_idx = idx
            app_name = matched

    if app_idx is not None and app_name is not None:
        # Each terminal tab runs unrelated work (a shell, an agent session, a daemon
        # started from it), so a tab is its own owner rather than part of the terminal.
        tab: str | None = None
        owner_end = app_idx + 1
        for idx in range(app_idx + 1, len(parts)):
            tm = _TAB_SCOPE_RE.match(parts[idx])
            if tm is not None:
                tab = tm.group(1)
                owner_end = idx + 1
        owner_cg = "/" + "/".join(parts[:owner_end])
        return Owner(app=app_name, unit=None, tab=tab), owner_cg

    slice_idx: int | None = None
    for idx, part in enumerate(parts):
        if part in ("app.slice", "session.slice"):
            slice_idx = idx

    if slice_idx is not None:
        svc_idx: int | None = None
        svc_name: str | None = None
        for idx in range(slice_idx + 1, len(parts)):
            part = parts[idx]
            if part.endswith(".service"):
                svc_idx = idx
                svc_name = _decode_escaped(part[: -len(".service")])
        if svc_idx is not None and svc_name is not None:
            owner_cg = "/" + "/".join(parts[: svc_idx + 1])
            return Owner(app=None, unit=svc_name, tab=None), owner_cg

    owner_cg = "/" + "/".join(parts)
    return Owner(app=None, unit=parts[-1], tab=None), owner_cg


def owner_of(cgroup_path: str) -> Owner:
    owner, _ = resolve_owner(cgroup_path)
    return owner


def _pick_held_by(members: list[Proc]) -> Proc:
    by_pid = {p.pid: p for p in members}
    children: dict[int, list[Proc]] = {p.pid: [] for p in members}
    roots: list[Proc] = []
    for p in members:
        if p.ppid in by_pid and p.ppid != p.pid:
            children[p.ppid].append(p)
        else:
            roots.append(p)
    if not roots:
        roots = list(members)

    def subtree_kb(root: Proc) -> int:
        total = 0
        stack = [root]
        seen: set[int] = set()
        while stack:
            cur = stack.pop()
            if cur.pid in seen:
                continue
            seen.add(cur.pid)
            total += cur.rss_kb + cur.swap_kb
            stack.extend(children.get(cur.pid, ()))
        return total

    held = max(roots, key=lambda r: (subtree_kb(r), r.rss_kb + r.swap_kb, -r.pid))
    # A tab's shell or a daemon's supervisor is the root but holds little itself:
    # follow the child that holds most of the subtree down to the real holder.
    while True:
        kids = children.get(held.pid, ())
        if not kids:
            return held
        heaviest = max(kids, key=lambda c: (subtree_kb(c), -c.pid))
        if subtree_kb(heaviest) * 2 <= subtree_kb(held):
            return held
        held = heaviest


def group_by_owner(
    procs: dict[int, Proc] | Iterable[Proc],
    cgroup_root: str | Path = "/sys/fs/cgroup",
) -> list[OwnerUsage]:
    proc_list = list(procs.values()) if isinstance(procs, dict) else list(procs)
    buckets: dict[str, list[ tuple[Proc, Owner] ]] = {}
    for p in proc_list:
        owner, owner_cg = resolve_owner(p.cgroup)
        buckets.setdefault(owner_cg, []).append((p, owner))

    usages: list[OwnerUsage] = []
    for owner_cg, items in buckets.items():
        members = [p for p, _ in items]
        # Members of one owner cgroup resolve to the same owner.
        group_owner = items[0][1]

        rss_kb = sum(p.rss_kb for p in members)
        swap_kb = sum(p.swap_kb for p in members)
        cg_mem = read_cgroup_memory(cgroup_root, owner_cg)
        cg_bytes = cg_mem[0] if cg_mem is not None else None
        cg_swap_bytes = cg_mem[1] if cg_mem is not None else None
        held_by = _pick_held_by(members)

        usages.append(
            OwnerUsage(
                owner=group_owner,
                cgroup=owner_cg,
                rss_kb=rss_kb,
                swap_kb=swap_kb,
                cgroup_bytes=cg_bytes,
                cgroup_swap_bytes=cg_swap_bytes,
                held_by=held_by,
            )
        )

    usages = [_without_nested(u, usages) for u in usages]
    usages.sort(key=lambda u: (-u.total_bytes, u.cgroup))
    return usages


def _without_nested(usage: OwnerUsage, usages: list[OwnerUsage]) -> OwnerUsage:
    # A terminal's scope counts its tabs' memory too; each tab is reported on its own row.
    if usage.cgroup_bytes is None or usage.cgroup_swap_bytes is None:
        return usage
    prefix = usage.cgroup.rstrip("/") + "/"
    nested = [u for u in usages if u.cgroup.startswith(prefix)]
    if not nested:
        return usage
    return replace(
        usage,
        cgroup_bytes=max(usage.cgroup_bytes - sum(u.ram_bytes for u in nested), 0),
        cgroup_swap_bytes=max(usage.cgroup_swap_bytes - sum(u.swap_bytes for u in nested), 0),
    )
