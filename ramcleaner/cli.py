# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import math
import time
from collections.abc import Sequence

from ramcleaner.config import ConfigError, load_config
from ramcleaner.detect import detect
from ramcleaner.history import default_history_path, load_history
from ramcleaner.owner import OwnerUsage, group_by_owner
from ramcleaner.procscan import clock_ticks, read_uptime, scan_processes


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
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between CPU samples (default: 2.0).",
    )
    report_p.add_argument(
        "--history-file",
        default=default_history_path(),
        help="History file to read (default: XDG state directory).",
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
        if not math.isfinite(args.interval) or args.interval < 0:
            parser.error("--interval must be finite and non-negative")
        try:
            config = load_config()
        except (ConfigError, OSError) as exc:
            parser.error(str(exc))
        history = load_history(args.history_file)
        first = scan_processes(proc_root=args.proc_root)
        time.sleep(args.interval)
        procs = scan_processes(proc_root=args.proc_root)
        findings = detect(
            first, procs, config, read_uptime(args.proc_root), clock_ticks(),
            history, args.cgroup_root,
        )
        usages = group_by_owner(procs, cgroup_root=args.cgroup_root)
        print("RAM = anonymous memory, page cache excluded")
        for usage in usages[: max(args.top, 0)]:
            print(_format_row(usage))
        print("Findings:" if findings else "Findings: none")
        for finding in findings:
            print(
                f"{finding.rule}  {finding.owner_label}  {len(finding.pids)} pids  "
                f"{finding.rss_kb / 1024:.1f} MB RAM  {finding.swap_kb / 1024:.1f} MB swap  "
                f"{finding.reason}"
            )
        return 0

    return 0
