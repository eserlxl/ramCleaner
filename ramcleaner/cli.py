# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
from collections.abc import Sequence

from ramcleaner.owner import OwnerUsage, group_by_owner
from ramcleaner.procscan import scan_processes


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ramcleaner",
        description="Report memory usage attributed to owning applications and units.",
    )
    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Path to /proc root (test aid; default: /proc).",
    )
    parser.add_argument(
        "--cgroup-root",
        default="/sys/fs/cgroup",
        help="Path to cgroup v2 root (test aid; default: /sys/fs/cgroup).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    report_p = subparsers.add_parser(
        "report",
        help="Print memory usage grouped by owning application or unit.",
    )
    report_p.add_argument(
        "--top",
        type=int,
        default=15,
        help="Maximum number of owners to display (default: 15).",
    )
    report_p.add_argument(
        "--proc-root",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    report_p.add_argument(
        "--cgroup-root",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    return parser


def _format_row(usage: OwnerUsage) -> str:
    ram_mb = usage.ram_bytes / (1024 * 1024)
    swap_mb = usage.swap_bytes / (1024 * 1024)
    held = f"{usage.held_by.comm} (pid {usage.held_by.pid})"
    return f"{usage.owner.label:<32}  {held:<28}  {ram_mb:7.1f} MB RAM  {swap_mb:7.1f} MB swap"


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "report":
        procs = scan_processes(proc_root=args.proc_root)
        usages = group_by_owner(procs, cgroup_root=args.cgroup_root)
        for usage in usages[: max(args.top, 0)]:
            print(_format_row(usage))
        return 0

    return 0
