# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import math
import sys
import time
from collections.abc import Sequence

from ramcleaner.actions import stop_finding
from ramcleaner.config import Config, ConfigError, load_config
from ramcleaner.detect import Finding, detect
from ramcleaner.history import default_history_path, load_history
from ramcleaner.notify import NotifySend
from ramcleaner.owner import OwnerUsage, group_by_owner
from ramcleaner.procscan import Proc, clock_ticks, read_uptime, scan_processes
from ramcleaner.watch import format_finding, format_stop_result, run_watch


def _add_scan_options(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between CPU samples (default: 2.0).",
    )
    subparser.add_argument(
        "--history-file",
        default=default_history_path(),
        help="History file to read (default: XDG state directory).",
    )
    subparser.add_argument(
        "--proc-root",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    subparser.add_argument(
        "--cgroup-root",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )


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
    _add_scan_options(report_p)
    report_p.add_argument(
        "--top",
        type=int,
        default=15,
        help="Maximum number of owners to display (default: 15).",
    )

    clean_p = subparsers.add_parser(
        "clean",
        help="Interactively approve and stop reported findings.",
    )
    _add_scan_options(clean_p)
    clean_p.add_argument(
        "--force",
        action="store_true",
        help="Send SIGKILL to processes that survive SIGTERM.",
    )

    watch_p = subparsers.add_parser(
        "watch",
        help="Scan once, record history, and notify about new findings.",
    )
    _add_scan_options(watch_p)
    return parser


def _format_row(usage: OwnerUsage) -> str:
    ram_mb = usage.ram_bytes / (1024 * 1024)
    swap_mb = usage.swap_bytes / (1024 * 1024)
    held = f"{usage.held_by.comm} (pid {usage.held_by.pid})"
    return f"{usage.owner.label:<32}  {held:<28}  {ram_mb:7.1f} MB RAM  {swap_mb:7.1f} MB swap"


def _scan_and_detect(
    args: argparse.Namespace,
    config: Config,
) -> tuple[dict[int, Proc], list[Finding]]:
    history = load_history(args.history_file)
    first = scan_processes(proc_root=args.proc_root)
    time.sleep(args.interval)
    procs = scan_processes(proc_root=args.proc_root)
    findings = detect(
        first,
        procs,
        config,
        read_uptime(args.proc_root),
        clock_ticks(),
        history,
    )
    return procs, findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in ("report", "clean", "watch"):
        if not math.isfinite(args.interval) or args.interval < 0:
            parser.error("--interval must be finite and non-negative")
        if args.command == "clean" and not sys.stdin.isatty():
            print(
                "clean needs an interactive terminal; ramcleaner watch sends notifications",
                file=sys.stderr,
            )
            return 2
        try:
            config = load_config()
        except (ConfigError, OSError) as exc:
            parser.error(str(exc))

        if args.command == "watch":
            return run_watch(args, config, notifier=NotifySend())

        procs, findings = _scan_and_detect(args, config)

        if args.command == "report":
            usages = group_by_owner(procs, cgroup_root=args.cgroup_root)
            print("RAM = anonymous memory, page cache excluded")
            for usage in usages[: max(args.top, 0)]:
                print(_format_row(usage))
            print("Findings:" if findings else "Findings: none")
            for finding in findings:
                print(format_finding(finding))
            return 0

        if not findings:
            print("Findings: none")
            return 0
        exit_code = 0
        for finding in findings:
            print(format_finding(finding))
            while True:
                try:
                    answer = input("Stop it? [y/N/d] ")
                except EOFError:
                    answer = ""
                choice = answer.strip().lower()
                if choice in ("d", "details"):
                    for proc in finding.procs:
                        mb = (proc.rss_kb + proc.swap_kb) // 1024
                        cmd = " ".join(proc.cmdline) or proc.comm
                        print(f"  {proc.pid}  {mb} MB  {cmd}")
                    continue
                if choice in ("y", "yes"):
                    result = stop_finding(
                        finding,
                        config,
                        proc_root=args.proc_root,
                        force=args.force,
                    )
                    print(format_stop_result(result))
                    if result.still_alive:
                        exit_code = 1
                break
        return exit_code

    return 0
