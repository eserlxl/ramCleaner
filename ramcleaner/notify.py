# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence

from ramcleaner.detect import Finding

_BASE_ARGV = ("notify-send", "--app-name=ramCleaner", "--urgency=normal")


def _format_notification(finding: Finding) -> tuple[str, str]:
    mb = (finding.rss_kb + finding.swap_kb) // 1024
    summary = f"{finding.owner_label}: {mb} MB in {len(finding.pids)} processes"
    pids = ", ".join(str(pid) for pid in finding.pids)
    body = f"{finding.reason} (PIDs: {pids})"
    return summary, body


class NotifySend:
    def ask(self, findings: Sequence[Finding]) -> dict[str, str]:
        running: list[tuple[str, subprocess.Popen[str]]] = []
        answers: dict[str, str] = {}
        warning: str | None = None

        for finding in findings:
            summary, body = _format_notification(finding)
            argv = [
                *_BASE_ARGV,
                "--action=stop=Stop",
                "--action=ignore=Ignore",
                summary,
                body,
            ]
            try:
                proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
            except OSError as exc:
                answers[finding.key] = "unavailable"
                if warning is None:
                    warning = f"Warning: notify-send unavailable: {exc}"
            else:
                running.append((finding.key, proc))

        for key, proc in running:
            stdout, _ = proc.communicate()
            if proc.returncode != 0:
                answers[key] = "unavailable"
                if warning is None:
                    warning = f"Warning: notify-send exited with status {proc.returncode}"
            else:
                answers[key] = (stdout or "").strip()

        if warning is not None:
            print(warning, file=sys.stderr)
        return answers

    def inform(self, summary: str, body: str = "") -> None:
        argv = [*_BASE_ARGV, summary, body]
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
            proc.communicate()
        except OSError as exc:
            print(f"Warning: notify-send unavailable: {exc}", file=sys.stderr)
            return
        if proc.returncode != 0:
            print(
                f"Warning: notify-send exited with status {proc.returncode}",
                file=sys.stderr,
            )
