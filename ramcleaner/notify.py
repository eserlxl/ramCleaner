# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Sequence

from ramcleaner.detect import Finding, format_size

_BASE_ARGV = ("notify-send", "--app-name=ramCleaner", "--urgency=normal")
_INFORM_TIMEOUT_S = 10.0


def _format_notification(finding: Finding) -> tuple[str, str]:
    summary = (
        f"{finding.owner_label}: {format_size(finding.rss_kb + finding.swap_kb)} "
        f"in {len(finding.pids)} processes"
    )
    pids = ", ".join(str(pid) for pid in finding.pids)
    body = f"{finding.reason} (PIDs: {pids})"
    return summary, body


class NotifySend:
    def ask(
        self, findings: Sequence[Finding], timeout_s: int
    ) -> dict[str, str]:
        running: list[tuple[str, subprocess.Popen[str]]] = []
        answers: dict[str, str] = {}
        warning: str | None = None
        # The popup must outlive our deadline: if the server closed it first, notify-send would
        # print nothing, which reads as a dismissal and would suppress the finding.
        expire_ms = int((timeout_s + 60) * 1000)

        for finding in findings:
            summary, body = _format_notification(finding)
            argv = [
                *_BASE_ARGV,
                f"--expire-time={expire_ms}",
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

        deadline = time.monotonic() + timeout_s
        for key, proc in running:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                stdout, _ = proc.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                answers[key] = "timeout"
                continue
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
            try:
                proc.communicate(timeout=_INFORM_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=_INFORM_TIMEOUT_S)
                except (subprocess.TimeoutExpired, OSError):
                    if proc.stdout is not None and not proc.stdout.closed:
                        proc.stdout.close()
                    try:
                        proc.wait(timeout=_INFORM_TIMEOUT_S)
                    except (subprocess.TimeoutExpired, OSError) as exc:
                        print(
                            f"Warning: failed to reap notify-send: {exc}",
                            file=sys.stderr,
                        )
                        return
        except OSError as exc:
            print(f"Warning: notify-send unavailable: {exc}", file=sys.stderr)
            return
        if proc.returncode != 0:
            print(
                f"Warning: notify-send exited with status {proc.returncode}",
                file=sys.stderr,
            )
