# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import html
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence

from ramcleaner.detect import Finding, format_size

_BASE_ARGV = ("notify-send", "--app-name=ramCleaner", "--urgency=normal")
_INFORM_TIMEOUT_S = 10.0
_HIDE_CHOICES = ("1 hour", "6 hours", "24 hours", "Until reboot")


def _spawn_dialog(argv: Sequence[str], timeout_s: float) -> subprocess.CompletedProcess[str]:
    # Without a display zenity exits 1, which would read as a cancel and hide nothing.
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        raise OSError("no display")
    # zenity writes GTK warnings to stderr; they are not part of watch's output.
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, "")


def run_hide_dialog(
    finding: Finding,
    remaining_s: float,
    runner: Callable[[Sequence[str], float], subprocess.CompletedProcess[str]] | None = None,
) -> tuple[str, str | None]:
    seconds = int(remaining_s)
    # zenity treats --timeout=0 as no timeout and would outlive the ask deadline.
    if seconds < 1:
        return "timeout", None
    # zenity renders --text as Pango markup; a cgroup label must stay literal.
    text = html.escape(
        f"Hide {finding.owner_label} "
        f"({format_size(finding.rss_kb + finding.swap_kb)}) for:",
        quote=False,
    )
    argv = [
        "zenity",
        "--forms",
        "--title=ramCleaner",
        f"--text={text}",
        "--add-combo=Hide for",
        "--combo-values=" + "|".join(_HIDE_CHOICES),
        f"--timeout={seconds}",
    ]
    try:
        completed = (runner if runner is not None else _spawn_dialog)(argv, remaining_s)
    except subprocess.TimeoutExpired:
        return "timeout", None
    except OSError as exc:
        return (
            "fallback",
            f"Warning: zenity unavailable, hiding for the default duration: {exc}",
        )
    if completed.returncode == 0:
        choice = (completed.stdout or "").strip()
        if choice in _HIDE_CHOICES:
            return choice, None
        return "cancel", None
    if completed.returncode == 1:
        return "cancel", None
    if completed.returncode == 5:
        return "timeout", None
    warning = (
        f"Warning: zenity exited with status {completed.returncode}, "
        "hiding for the default duration"
    )
    return "fallback", warning


def _format_notification(finding: Finding) -> tuple[str, str]:
    summary = (
        f"{finding.owner_label}: {format_size(finding.rss_kb + finding.swap_kb)} "
        f"in {len(finding.pids)} processes"
    )
    pids = ", ".join(str(pid) for pid in finding.pids)
    # Summary is plain text; Plasma renders the body as markup.
    body = html.escape(f"{finding.reason} (PIDs: {pids})", quote=False)
    return summary, body


class NotifySend:
    def __init__(
        self,
        dialog_runner: (
            Callable[[Sequence[str], float], subprocess.CompletedProcess[str]] | None
        ) = None,
    ) -> None:
        self._dialog_runner = dialog_runner

    def ask(
        self, findings: Sequence[Finding], timeout_s: int
    ) -> dict[str, str]:
        running: list[tuple[Finding, subprocess.Popen[str]]] = []
        answers: dict[str, str] = {}
        warning: str | None = None
        dialog_warning: str | None = None
        # The popup must outlive our deadline: if the server closed it first, notify-send would
        # print nothing, which reads as a dismissal and would suppress the finding.
        expire_ms = int((timeout_s + 60) * 1000)

        for finding in findings:
            summary, body = _format_notification(finding)
            # Other-user warnings are information only: Hide... only. Closing
            # the popup already suppresses them for ignore_for_hours.
            if finding.rule == "other-user":
                actions = ["--action=hide=Hide..."]
            else:
                actions = [
                    "--action=stop=Stop",
                    "--action=later=Later",
                    "--action=hide=Hide...",
                ]
            argv = [
                *_BASE_ARGV,
                f"--expire-time={expire_ms}",
                *actions,
                # Labels can come from another user's cgroup names; never parse them as options.
                "--",
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
                running.append((finding, proc))

        deadline = time.monotonic() + timeout_s
        # A later notify-send can exit while an earlier one is still open;
        # reading in spawn order would delay that finding's Hide dialog.
        pending = running
        while pending:
            still: list[tuple[Finding, subprocess.Popen[str]]] = []
            for finding, proc in pending:
                if proc.poll() is None:
                    still.append((finding, proc))
                    continue
                key = finding.key
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
                    answer = (stdout or "").strip()
                    if answer == "hide":
                        token, hide_warning = run_hide_dialog(
                            finding,
                            max(0.0, deadline - time.monotonic()),
                            self._dialog_runner,
                        )
                        answers[key] = token
                        if hide_warning is not None and dialog_warning is None:
                            dialog_warning = hide_warning
                    else:
                        answers[key] = answer
            pending = still
            if not pending:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        for finding, proc in pending:
            proc.kill()
            proc.communicate()
            answers[finding.key] = "timeout"

        if warning is not None:
            print(warning, file=sys.stderr)
        if dialog_warning is not None:
            print(dialog_warning, file=sys.stderr)
        return answers

    def inform(self, summary: str, body: str = "") -> None:
        argv = [*_BASE_ARGV, "--", summary, body]
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
