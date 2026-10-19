# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import fcntl
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from ramcleaner.actions import StopResult
from ramcleaner.cli import main
from ramcleaner.config import Config
from ramcleaner.detect import Finding, format_size
from ramcleaner.history import load_history
from ramcleaner.notify import NotifySend, _format_notification, run_hide_dialog
from ramcleaner.owner import resolve_owner
from ramcleaner.procscan import read_boot_id
from ramcleaner.watch import (
    format_finding,
    format_stop_result,
    load_ignored,
    run_watch,
    save_ignored,
)
from tests.fakeproc import build_tree, write_proc


class _FakeNotifier:
    def __init__(self, answers: dict[str, str] | str = "ignore") -> None:
        self.answers = answers
        self.asked: list[list[Finding]] = []
        self.timeouts: list[int] = []
        self.informed: list[tuple[str, str]] = []

    def ask(self, findings: list[Finding], timeout_s: int = 600) -> dict[str, str]:
        self.asked.append(list(findings))
        self.timeouts.append(timeout_s)
        if isinstance(self.answers, str):
            return {finding.key: self.answers for finding in findings}
        return {
            finding.key: self.answers.get(finding.key, "") for finding in findings
        }

    def inform(self, summary: str, body: str = "") -> None:
        self.informed.append((summary, body))


class _FakeStopper:
    def __init__(self, still_alive: tuple[int, ...] = ()) -> None:
        self.still_alive = still_alive
        self.calls: list[tuple[Finding, Config, object]] = []

    def __call__(
        self,
        finding: Finding,
        config: Config,
        *,
        proc_root: object,
    ) -> StopResult:
        self.calls.append((finding, config, proc_root))
        return StopResult(
            finding_key=finding.key,
            method="SIGTERM",
            stopped=(10, 11, 12, 13),
            still_alive=self.still_alive,
            skipped=(),
        )


class _FakePopen:
    def __init__(
        self,
        argv: list[str],
        stdout_text: str = "",
        returncode: int = 0,
        *,
        expire_on_first_communicate: bool = False,
        expire_cleanup_communicate: bool = False,
        fail_cleanup_wait: bool = False,
    ) -> None:
        self.argv = argv
        self._stdout_text = stdout_text
        self.returncode = returncode
        self._expire_on_first = expire_on_first_communicate
        self._expire_cleanup = expire_cleanup_communicate
        self._fail_cleanup_wait = fail_cleanup_wait
        self.communicated = False
        self.communicate_timeouts: list[float | None] = []
        self.wait_timeouts: list[float | None] = []
        self.killed = False
        self.reaped = False
        # inform() inspects stdout after a failed cleanup communicate.
        self.stdout = None

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if self._fail_cleanup_wait:
            raise subprocess.TimeoutExpired(self.argv, timeout or 0.0)
        return self.returncode

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self.communicated = True
        self.communicate_timeouts.append(timeout)
        if self._expire_on_first:
            self._expire_on_first = False
            raise subprocess.TimeoutExpired(self.argv, timeout or 0.0)
        if self.killed and self._expire_cleanup:
            raise subprocess.TimeoutExpired(self.argv, timeout or 0.0)
        if self.killed:
            self.reaped = True
        return self._stdout_text, ""


def _assert_positive_timeouts(test: unittest.TestCase, timeouts: list[float | None]) -> None:
    test.assertTrue(timeouts)
    for timeout in timeouts:
        test.assertIsInstance(timeout, (int, float))
        test.assertGreater(timeout, 0)


class WatchTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_dir = self.root / "state" / "ramcleaner"
        self.history_file = self.state_dir / "history.json"
        self.ignored_file = self.state_dir / "ignored.json"
        environment = patch.dict(
            os.environ,
            {
                "XDG_CONFIG_HOME": str(self.root / "config"),
                "XDG_STATE_HOME": str(self.root / "state"),
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

        self.cgroup = "/app.slice/app-org.kde.yakuake-1.scope/tab(850422).scope"
        self.proc_root, self.cgroup_root = build_tree(
            self.root,
            [
                {
                    "pid": pid,
                    "ppid": 20,
                    "comm": "bun",
                    "cmdline": ("bun", "/opt/context-mode/start.mjs"),
                    "rss_kb": 256 * 1024,
                    "swap_kb": 64 * 1024,
                    "start_ticks": 100,
                    "cpu_ticks": 10,
                    "cgroup": self.cgroup,
                }
                for pid in range(10, 15)
            ]
            + [
                {
                    "pid": 30,
                    "ppid": 20,
                    "comm": "defunct",
                    "state": "Z",
                    "rss_kb": 0,
                    "swap_kb": 0,
                    "start_ticks": 200,
                    "cgroup": self.cgroup,
                }
            ],
        )

    def _args(self, interval: float = 0.0) -> argparse.Namespace:
        return argparse.Namespace(
            interval=interval,
            history_file=self.history_file,
            proc_root=self.proc_root,
            cgroup_root=self.cgroup_root,
        )

    def _other_user_args(self) -> tuple[argparse.Namespace, str]:
        service_uid = 0 if os.getuid() != 0 else 65534
        journald = "/system.slice/systemd-journald.service"
        proc_root, cgroup_root = build_tree(
            self.root / "other-users",
            [
                {
                    "pid": 80,
                    "ppid": 1,
                    "comm": "systemd-journald",
                    "uid": service_uid,
                    "rss_kb": 512 * 1024,
                    "swap_kb": 0,
                    "start_ticks": 100,
                    "cgroup": journald,
                },
                {
                    "pid": 81,
                    "ppid": 1,
                    "comm": "tiny",
                    "uid": service_uid,
                    "rss_kb": 100 * 1024,
                    "swap_kb": 0,
                    "start_ticks": 100,
                    "cgroup": "/system.slice/tiny.service",
                },
            ],
        )
        args = argparse.Namespace(
            interval=0.0,
            history_file=self.history_file,
            proc_root=proc_root,
            cgroup_root=cgroup_root,
        )
        _, owner_cg = resolve_owner(journald)
        return args, f"other-user:{owner_cg}"

    def _run_hide(self, config: Config, stamp: float, runner) -> tuple[int, str, str]:
        def fake_popen(argv, *, stdout=None, text=None):
            return _FakePopen(argv, stdout_text="hide\n")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            patch("ramcleaner.notify.time.monotonic", return_value=1000.0),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = run_watch(
                self._args(),
                config,
                notifier=NotifySend(dialog_runner=runner),
                now=lambda: stamp,
            )
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_records_history_entry_per_run(self) -> None:
        notifier = _FakeNotifier("ignore")
        with redirect_stdout(io.StringIO()):
            rc1 = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1000.0)
            rc2 = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1900.0)
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        history = load_history(self.history_file)
        self.assertEqual([entry["time"] for entry in history], [1000.0, 1900.0])
        self.assertEqual(history[0]["procs"]["10:100"], 320 * 1024)
        self.assertEqual(history[0]["zombies"], ["30:200"])

    def test_boot_id_recorded_when_readable(self) -> None:
        notifier = _FakeNotifier("ignore")
        with (
            patch("ramcleaner.watch.read_boot_id", wraps=read_boot_id) as mocked,
            redirect_stdout(io.StringIO()),
        ):
            rc = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1000.0)
        self.assertEqual(rc, 0)
        mocked.assert_called_once_with(self.proc_root)
        history = load_history(self.history_file)
        self.assertEqual(history[0]["boot_id"], "boot-fixture")

    def test_boot_id_omitted_when_unavailable(self) -> None:
        boot = self.proc_root / "sys/kernel/random/boot_id"
        for case in ("missing", "unreadable"):
            with self.subTest(case=case):
                self.history_file.unlink(missing_ok=True)
                if boot.is_dir():
                    boot.rmdir()
                elif boot.exists():
                    boot.unlink()
                if case == "unreadable":
                    boot.parent.mkdir(parents=True, exist_ok=True)
                    boot.mkdir()
                notifier = _FakeNotifier("ignore")
                with redirect_stdout(io.StringIO()):
                    rc = run_watch(
                        self._args(), Config(), notifier=notifier, now=lambda: 1000.0
                    )
                self.assertEqual(rc, 0)
                history = load_history(self.history_file)
                self.assertEqual(len(history), 1)
                self.assertNotIn("boot_id", history[0])

    def test_suppression_window_and_expiry_pruning(self) -> None:
        config = Config(ignore_for_hours=2)
        for outcome in ("ignore", ""):
            with self.subTest(outcome=outcome):
                self.ignored_file.unlink(missing_ok=True)
                self.history_file.unlink(missing_ok=True)
                notifier = _FakeNotifier(outcome)
                stopper = _FakeStopper()

                with redirect_stdout(io.StringIO()):
                    rc1 = run_watch(
                        self._args(),
                        config,
                        notifier=notifier,
                        stopper=stopper,
                        now=lambda: 1000.0,
                    )
                    rc2 = run_watch(
                        self._args(),
                        config,
                        notifier=notifier,
                        stopper=stopper,
                        now=lambda: 1000.0 + 3600.0,
                    )
                self.assertEqual((rc1, rc2), (0, 0))
                self.assertEqual(len(notifier.asked), 1)
                self.assertEqual(stopper.calls, [])
                ignored = load_ignored(self.ignored_file)
                self.assertEqual(len(ignored), 1)
                key = next(iter(ignored))
                self.assertEqual(ignored[key], 1000.0 + 7200.0)

                # Add a stale key and advance past expiry: finding is asked again and stale key is dropped.
                raw = json.loads(self.ignored_file.read_text(encoding="utf-8"))
                raw["stale:key"] = 2000.0
                self.ignored_file.write_text(json.dumps(raw), encoding="utf-8")

                with redirect_stdout(io.StringIO()):
                    rc3 = run_watch(
                        self._args(),
                        config,
                        notifier=notifier,
                        stopper=stopper,
                        now=lambda: 1000.0 + 7200.0,
                    )
                self.assertEqual(rc3, 0)
                self.assertEqual(len(notifier.asked), 2)
                updated = load_ignored(self.ignored_file)
                self.assertEqual(set(updated.keys()), {key})
                self.assertEqual(updated[key], 1000.0 + 14400.0)

    def test_boot_suppression_same_boot_other_boot_prune_and_mixed_round_trip(self) -> None:
        _, owner_cgroup = resolve_owner(self.cgroup)
        key = f"idle-clones:{owner_cgroup}:{('bun', '/opt/context-mode/start.mjs')}"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        mixed = {key: {"boot_id": "boot-fixture"}, "kept:number": 9000.0}
        self.ignored_file.write_text(json.dumps(mixed), encoding="utf-8")

        notifier = _FakeNotifier("ignore")
        with redirect_stdout(io.StringIO()):
            rc = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1000.0)
        self.assertEqual(rc, 0)
        self.assertEqual(notifier.asked, [])
        self.assertEqual(load_ignored(self.ignored_file), mixed)

        save_ignored(self.ignored_file, load_ignored(self.ignored_file), 1000.0, "boot-fixture")
        raw = json.loads(self.ignored_file.read_text(encoding="utf-8"))
        self.assertEqual(raw[key], {"boot_id": "boot-fixture"})
        self.assertEqual(raw["kept:number"], 9000.0)
        self.assertEqual(load_ignored(self.ignored_file), mixed)

        self.history_file.unlink(missing_ok=True)
        self.ignored_file.write_text(
            json.dumps({key: {"boot_id": "other-boot"}}),
            encoding="utf-8",
        )
        notifier = _FakeNotifier("timeout")
        with redirect_stdout(io.StringIO()):
            rc = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 2000.0)
        self.assertEqual(rc, 0)
        self.assertEqual(len(notifier.asked), 1)
        self.assertEqual(load_ignored(self.ignored_file), {})

    def test_pruning_an_expired_entry_keeps_a_current_boot_entry(self) -> None:
        _, owner_cgroup = resolve_owner(self.cgroup)
        key = f"idle-clones:{owner_cgroup}:{('bun', '/opt/context-mode/start.mjs')}"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ignored_file.write_text(
            json.dumps({key: {"boot_id": "boot-fixture"}, "expired:number": 500.0}),
            encoding="utf-8",
        )
        notifier = _FakeNotifier("ignore")
        with redirect_stdout(io.StringIO()):
            rc = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1000.0)
        self.assertEqual(rc, 0)
        self.assertEqual(notifier.asked, [])
        self.assertEqual(load_ignored(self.ignored_file), {key: {"boot_id": "boot-fixture"}})

    def test_malformed_ignored_warns_and_treats_as_empty(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ignored_file.write_text("{bad json", encoding="utf-8")
        notifier = _FakeNotifier("ignore")
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            rc = run_watch(self._args(), Config(), notifier=notifier, now=lambda: 1000.0)
        self.assertEqual(rc, 0)
        self.assertIn("Warning:", stderr.getvalue())
        self.assertEqual(len(notifier.asked), 1)

    def test_stop_action_calls_stopper_and_informs_and_reports_survivors(self) -> None:
        for still_alive, expected_rc in (((), 0), ((14,), 1)):
            with self.subTest(still_alive=still_alive):
                self.ignored_file.unlink(missing_ok=True)
                self.history_file.unlink(missing_ok=True)
                notifier = _FakeNotifier("stop")
                stopper = _FakeStopper(still_alive=still_alive)

                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    rc = run_watch(
                        self._args(),
                        Config(),
                        notifier=notifier,
                        stopper=stopper,
                        now=lambda: 5000.0,
                    )
                self.assertEqual(rc, expected_rc)
                self.assertIn("idle-clones", stdout.getvalue())
                self.assertEqual(len(stopper.calls), 1)
                self.assertEqual(stopper.calls[0][2], self.proc_root)
                self.assertEqual(len(notifier.informed), 1)
                summary, body = notifier.informed[0]
                self.assertIn("org.kde.yakuake tab 850422", summary)
                self.assertNotIn("still_alive", body)
                stopped = "4 processes stopped: 10, 11, 12, 13. Method: SIGTERM."
                if still_alive:
                    self.assertEqual(body, f"{stopped} Still running: 14.")
                else:
                    self.assertEqual(body, stopped)
                self.assertFalse(self.ignored_file.exists())

    def test_timeout_outcome_neither_stops_nor_suppresses_and_passes_configured_timeout(
        self,
    ) -> None:
        config = Config(ask_timeout_minutes=7)
        notifier = _FakeNotifier("timeout")
        stopper = _FakeStopper()

        stdout1 = io.StringIO()
        stdout2 = io.StringIO()
        with redirect_stdout(stdout1):
            rc1 = run_watch(
                self._args(),
                config,
                notifier=notifier,
                stopper=stopper,
                now=lambda: 1000.0,
            )
        with redirect_stdout(stdout2):
            rc2 = run_watch(
                self._args(),
                config,
                notifier=notifier,
                stopper=stopper,
                now=lambda: 1900.0,
            )

        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(notifier.timeouts, [420, 420])
        self.assertEqual(len(notifier.asked), 2)
        self.assertEqual(stopper.calls, [])
        self.assertEqual(notifier.informed, [])
        self.assertFalse(self.ignored_file.exists())
        self.assertEqual(load_ignored(self.ignored_file), {})
        self.assertIn("no answer, will ask again", stdout1.getvalue())
        self.assertIn("no answer, will ask again", stdout2.getvalue())

    def test_unavailable_outcome_neither_stops_nor_suppresses(self) -> None:
        notifier = _FakeNotifier("unavailable")
        stopper = _FakeStopper()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = run_watch(
                self._args(),
                Config(),
                notifier=notifier,
                stopper=stopper,
                now=lambda: 1000.0,
            )
        self.assertEqual(rc, 0)
        self.assertEqual(len(notifier.asked), 1)
        self.assertEqual(stopper.calls, [])
        self.assertEqual(load_ignored(self.ignored_file), {})
        self.assertIn("notification unavailable, will ask again", stdout.getvalue())

    def test_later_records_nothing_and_is_asked_again(self) -> None:
        notifier = _FakeNotifier("later")
        stopper = _FakeStopper()
        stdout1 = io.StringIO()
        stdout2 = io.StringIO()
        with redirect_stdout(stdout1):
            rc1 = run_watch(
                self._args(),
                Config(),
                notifier=notifier,
                stopper=stopper,
                now=lambda: 1000.0,
            )
        with redirect_stdout(stdout2):
            rc2 = run_watch(
                self._args(),
                Config(),
                notifier=notifier,
                stopper=stopper,
                now=lambda: 1900.0,
            )
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(len(notifier.asked), 2)
        self.assertEqual(stopper.calls, [])
        self.assertFalse(self.ignored_file.exists())
        self.assertEqual(load_ignored(self.ignored_file), {})
        self.assertIn("later, will ask again", stdout1.getvalue())
        self.assertIn("later, will ask again", stdout2.getvalue())

    def test_other_user_warning_is_sent_without_stop_action(self) -> None:
        args, _key = self._other_user_args()
        created: list[_FakePopen] = []
        stopper = _FakeStopper()

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, stdout_text="later\n")
            created.append(proc)
            return proc

        stdout = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            redirect_stdout(stdout),
        ):
            rc = run_watch(
                args,
                Config(),
                notifier=NotifySend(),
                stopper=stopper,
                now=lambda: 1000.0,
            )

        self.assertEqual(rc, 0)
        self.assertEqual(len(created), 1)
        actions = [arg for arg in created[0].argv if arg.startswith("--action=")]
        self.assertEqual(
            actions,
            ["--action=later=Later", "--action=hide=Hide..."],
        )
        self.assertNotIn("--action=stop=Stop", created[0].argv)
        self.assertIn("systemd-journald.service", created[0].argv[-2])
        self.assertIn("information only, not stopped", created[0].argv[-1])
        self.assertNotIn("tiny", " ".join(created[0].argv))
        self.assertIn("other-user", stdout.getvalue())
        self.assertIn("systemd-journald.service", stdout.getvalue())
        self.assertIn("later, will ask again", stdout.getvalue())
        self.assertNotIn("tiny", stdout.getvalue())
        self.assertEqual(stopper.calls, [])
        self.assertFalse(self.ignored_file.exists())

    def test_other_user_warning_is_never_stopped_even_on_a_stop_answer(self) -> None:
        args, key = self._other_user_args()
        notifier = _FakeNotifier("stop")
        stopper = _FakeStopper()
        with redirect_stdout(io.StringIO()):
            rc = run_watch(args, Config(), notifier=notifier, stopper=stopper, now=lambda: 1000.0)
        self.assertEqual(rc, 0)
        self.assertEqual([finding.key for finding in notifier.asked[0]], [key])
        self.assertEqual(stopper.calls, [])
        self.assertEqual(notifier.informed, [])
        self.assertFalse(self.ignored_file.exists())

    def test_other_users_notify_false_sends_no_warning(self) -> None:
        args, key = self._other_user_args()
        notifier = _FakeNotifier("later")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = run_watch(
                args,
                Config(other_users_notify=False),
                notifier=notifier,
                stopper=_FakeStopper(),
                now=lambda: 1000.0,
            )
        self.assertEqual(rc, 0)
        self.assertEqual(notifier.asked, [])
        self.assertNotIn(key, stdout.getvalue())
        self.assertNotIn("other-user", stdout.getvalue())

    def test_hidden_other_user_warning_stays_hidden(self) -> None:
        args, key = self._other_user_args()
        stamp = 1000.0
        notifier = _FakeNotifier("6 hours")
        stopper = _FakeStopper()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = run_watch(
                args,
                Config(),
                notifier=notifier,
                stopper=stopper,
                now=lambda: stamp,
            )
        self.assertEqual(rc, 0)
        self.assertEqual([finding.key for finding in notifier.asked[0]], [key])
        self.assertEqual(load_ignored(self.ignored_file), {key: stamp + 6 * 3600})
        self.assertNotIn("will ask again", stdout.getvalue())
        self.assertEqual(stopper.calls, [])

        stdout2 = io.StringIO()
        with redirect_stdout(stdout2):
            rc2 = run_watch(
                args,
                Config(),
                notifier=notifier,
                stopper=stopper,
                now=lambda: stamp + 10,
            )
        self.assertEqual(rc2, 0)
        self.assertEqual(len(notifier.asked), 1)
        self.assertEqual(stdout2.getvalue(), "")
        self.assertEqual(load_ignored(self.ignored_file), {key: stamp + 6 * 3600})

    def test_hide_menu_records_choice_or_leaves_finding_open(self) -> None:
        config = Config(ignore_for_hours=2)
        stamp = 1000.0
        _, owner_cgroup = resolve_owner(self.cgroup)
        key = f"idle-clones:{owner_cgroup}:{('bun', '/opt/context-mode/start.mjs')}"
        zenity_argv = [
            "zenity",
            "--forms",
            "--add-combo=Hide for",
            "--combo-values=1 hour|6 hours|24 hours|Until reboot",
            "--timeout=600",
        ]

        def run_answered(respond):
            self.ignored_file.unlink(missing_ok=True)
            self.history_file.unlink(missing_ok=True)
            seen: list[tuple[list[str], float]] = []

            def runner(argv, timeout_s, respond=respond, seen=seen):
                seen.append((list(argv), timeout_s))
                return respond(argv, timeout_s)

            rc, stdout, stderr = self._run_hide(config, stamp, runner)
            return rc, stdout, stderr, seen

        def chosen(text: str):
            def respond(argv, timeout_s):
                return subprocess.CompletedProcess(argv, 0, text, "")

            return respond

        expected = {
            "1 hour\n": stamp + 3600,
            "6 hours\n": stamp + 6 * 3600,
            "24 hours\n": stamp + 24 * 3600,
            "Until reboot\n": {"boot_id": "boot-fixture"},
        }
        for text, value in expected.items():
            with self.subTest(choice=text.strip()):
                rc, stdout, stderr, seen = run_answered(chosen(text))
                self.assertEqual(rc, 0)
                self.assertEqual(stderr, "")
                self.assertNotIn("will ask again", stdout)
                self.assertEqual(load_ignored(self.ignored_file), {key: value})
                self.assertEqual(seen, [(zenity_argv, 600.0)])

        def cancelled(argv, timeout_s):
            return subprocess.CompletedProcess(argv, 1, "", "")

        with self.subTest(choice="cancel"):
            rc, stdout, stderr, seen = run_answered(cancelled)
            self.assertEqual(rc, 0)
            self.assertEqual(stderr, "")
            self.assertIn("hide cancelled, will ask again", stdout)
            self.assertFalse(self.ignored_file.exists())
            self.assertEqual(seen, [(zenity_argv, 600.0)])

        def closed(argv, timeout_s):
            return subprocess.CompletedProcess(argv, 0, "\n", "")

        with self.subTest(choice="closed"):
            rc, stdout, stderr, _seen = run_answered(closed)
            self.assertEqual(rc, 0)
            self.assertEqual(stderr, "")
            self.assertIn("hide cancelled, will ask again", stdout)
            self.assertFalse(self.ignored_file.exists())

        def zenity_timeout(argv, timeout_s):
            return subprocess.CompletedProcess(argv, 5, "", "")

        with self.subTest(choice="zenity-timeout"):
            rc, stdout, stderr, _seen = run_answered(zenity_timeout)
            self.assertEqual(rc, 0)
            self.assertEqual(stderr, "")
            self.assertIn("no answer, will ask again", stdout)
            self.assertFalse(self.ignored_file.exists())

        def expired(argv, timeout_s):
            raise subprocess.TimeoutExpired(argv, timeout_s)

        with self.subTest(choice="dialog-wait-expired"):
            rc, stdout, stderr, _seen = run_answered(expired)
            self.assertEqual(rc, 0)
            self.assertEqual(stderr, "")
            self.assertIn("no answer, will ask again", stdout)
            self.assertFalse(self.ignored_file.exists())

        def missing(argv, timeout_s):
            raise FileNotFoundError("no zenity")

        with self.subTest(choice="missing"):
            rc, stdout, stderr, _seen = run_answered(missing)
            self.assertEqual(rc, 0)
            self.assertEqual(
                stderr.splitlines(),
                ["Warning: zenity unavailable, hiding for the default duration: no zenity"],
            )
            self.assertNotIn("will ask again", stdout)
            self.assertEqual(load_ignored(self.ignored_file), {key: stamp + 2 * 3600})

        def failed(argv, timeout_s):
            return subprocess.CompletedProcess(argv, 2, "", "")

        with self.subTest(choice="failed"):
            rc, stdout, stderr, _seen = run_answered(failed)
            self.assertEqual(rc, 0)
            self.assertEqual(
                stderr.strip(),
                "Warning: zenity exited with status 2, hiding for the default duration",
            )
            self.assertEqual(load_ignored(self.ignored_file), {key: stamp + 2 * 3600})

        boot = self.proc_root / "sys/kernel/random/boot_id"
        saved_boot = boot.read_text(encoding="utf-8")
        boot.unlink()
        try:
            with self.subTest(choice="until reboot without boot id"):
                rc, stdout, stderr, _seen = run_answered(chosen("Until reboot\n"))
                self.assertEqual(rc, 0)
                self.assertEqual(stderr, "")
                self.assertIn("no boot id, will ask again", stdout)
                self.assertFalse(self.ignored_file.exists())
        finally:
            boot.write_text(saved_boot, encoding="utf-8")

    def test_held_lock_returns_0_without_scanning(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_dir / "watch.lock"
        with lock_path.open("w", encoding="utf-8") as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            stderr = io.StringIO()
            notifier = _FakeNotifier("stop")
            with (
                patch("ramcleaner.watch.scan_processes") as scan,
                redirect_stderr(stderr),
            ):
                rc = run_watch(self._args(), Config(), notifier=notifier)
        self.assertEqual(rc, 0)
        self.assertEqual(stderr.getvalue().strip(), "another watch is running")
        scan.assert_not_called()
        self.assertEqual(notifier.asked, [])

    def test_cli_watch_dispatches_to_run_watch(self) -> None:
        with (
            patch("ramcleaner.cli.run_watch", return_value=0) as mocked_watch,
            redirect_stdout(io.StringIO()),
        ):
            rc = main(
                [
                    "watch",
                    "--interval",
                    "0",
                    "--history-file",
                    str(self.history_file),
                    "--proc-root",
                    str(self.proc_root),
                    "--cgroup-root",
                    str(self.cgroup_root),
                ]
            )
        self.assertEqual(rc, 0)
        mocked_watch.assert_called_once()
        self.assertIsInstance(mocked_watch.call_args.kwargs["notifier"], NotifySend)

    def test_ignored_listing_hides_expired_and_preserves_history(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        now = 1000.0
        active_until = now + 3600.0
        expired_until = now - 50.0
        self.ignored_file.write_text(
            json.dumps(
                {
                    "idle-clones:tab(850422).scope": active_until,
                    "expired:tab(850422).scope": expired_until,
                }
            ),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.time.time", return_value=now),
            redirect_stdout(stdout),
        ):
            rc = main(["ignored", "--history-file", str(self.history_file)])
        self.assertEqual(rc, 0)
        expected_iso = datetime.fromtimestamp(active_until).isoformat(timespec="seconds")
        expected_line = f"idle-clones:tab(850422).scope  until {expected_iso}"
        self.assertEqual(stdout.getvalue().splitlines(), [expected_line])
        self.assertFalse(self.history_file.exists())

    def test_ignored_listing_prints_until_reboot_for_current_boot(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        now = 1000.0
        active_until = now + 3600.0
        self.ignored_file.write_text(
            json.dumps(
                {
                    "idle-clones:same": {"boot_id": "boot-fixture"},
                    "idle-clones:other": {"boot_id": "other-boot"},
                    "idle-clones:timed": active_until,
                }
            ),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.read_boot_id", return_value="boot-fixture"),
            patch("ramcleaner.cli.time.time", return_value=now),
            redirect_stdout(stdout),
        ):
            rc = main(["ignored", "--history-file", str(self.history_file)])
        self.assertEqual(rc, 0)
        expected_iso = datetime.fromtimestamp(active_until).isoformat(timespec="seconds")
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "idle-clones:same  until reboot",
                f"idle-clones:timed  until {expected_iso}",
            ],
        )

    def test_ignored_listing_when_none_or_all_expired(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main(["ignored", "--history-file", str(self.history_file)])
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().strip(), "Suppressed findings: none")

        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ignored_file.write_text(
            json.dumps({"expired:key": 500.0}),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.time.time", return_value=1000.0),
            redirect_stdout(stdout),
        ):
            rc = main(["ignored", "--history-file", str(self.history_file)])
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().strip(), "Suppressed findings: none")
        self.assertFalse(self.history_file.exists())

    def test_ignored_clear_empties_file_and_allows_reask(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ignored_file.write_text(
            json.dumps({"idle-clones:app.slice/app-org.kde.yakuake-1.scope/tab(850422).scope": 5000.0}),
            encoding="utf-8",
        )
        self.assertEqual(len(load_ignored(self.ignored_file)), 1)

        rc = main(["ignored", "--history-file", str(self.history_file), "--clear"])
        self.assertEqual(rc, 0)
        self.assertEqual(load_ignored(self.ignored_file), {})
        self.assertFalse(self.history_file.exists())

        notifier = _FakeNotifier("ignore")
        with redirect_stdout(io.StringIO()):
            rc_watch = run_watch(
                self._args(), Config(), notifier=notifier, now=lambda: 1000.0
            )
        self.assertEqual(rc_watch, 0)
        self.assertEqual(len(notifier.asked), 1)

    def test_ignored_clear_when_lock_held_fails_with_exit_1(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        initial_data = {"idle-clones:tab(850422).scope": 5000.0}
        self.ignored_file.write_text(json.dumps(initial_data), encoding="utf-8")
        lock_path = self.state_dir / "watch.lock"

        with lock_path.open("w", encoding="utf-8") as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = main(["ignored", "--history-file", str(self.history_file), "--clear"])

        self.assertEqual(rc, 1)
        self.assertEqual(stderr.getvalue().strip(), "another watch is running")
        self.assertEqual(load_ignored(self.ignored_file), initial_data)
        self.assertFalse(self.history_file.exists())

    def test_ignored_uses_default_history_file(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ignored_file.write_text(
            json.dumps({"default:key": 2000.0}),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.time.time", return_value=1000.0),
            redirect_stdout(stdout),
        ):
            rc = main(["ignored"])
        self.assertEqual(rc, 0)
        expected_iso = datetime.fromtimestamp(2000.0).isoformat()
        self.assertEqual(
            stdout.getvalue().strip(),
            f"default:key  until {expected_iso}",
        )

        rc_clear = main(["ignored", "--clear"])
        self.assertEqual(rc_clear, 0)
        self.assertEqual(load_ignored(self.ignored_file), {})
        self.assertFalse(self.history_file.exists())

    def test_inform_failure_after_stop_keeps_later_finding_and_releases_lock(self) -> None:
        second_cgroup = "/app.slice/app-org.kde.kate-1.scope/tab(7).scope"
        for pid in range(40, 44):
            write_proc(
                self.proc_root,
                {
                    "pid": pid,
                    "ppid": 20,
                    "comm": "bun",
                    "cmdline": ("bun", "/opt/context-mode/start.mjs"),
                    "rss_kb": 256 * 1024,
                    "swap_kb": 64 * 1024,
                    "start_ticks": 100,
                    "cpu_ticks": 10,
                    "cgroup": second_cgroup,
                },
            )
        _, owner_cgroup = resolve_owner(second_cgroup)
        command = ("bun", "/opt/context-mode/start.mjs")
        expected_key = f"idle-clones:{owner_cgroup}:{command}"
        stamp = 5000.0
        config = Config()
        modes = ("timeout", "failed_cleanup", "oserror", "nonzero")

        for mode in modes:
            for still_alive, expected_rc in (((), 0), ((14,), 1)):
                with self.subTest(mode=mode, still_alive=still_alive):
                    self.ignored_file.unlink(missing_ok=True)
                    self.history_file.unlink(missing_ok=True)
                    created: list[_FakePopen] = []

                    def fake_popen(argv, *, stdout=None, text=None, created=created, mode=mode):
                        if "--action=stop=Stop" in argv:
                            answered = any("--action=stop=Stop" in proc.argv for proc in created)
                            answer = "ignore\n" if answered else "stop\n"
                            proc = _FakePopen(argv, stdout_text=answer)
                            created.append(proc)
                            return proc
                        if mode == "oserror":
                            raise OSError("inform notify-send failed")
                        if mode == "nonzero":
                            proc = _FakePopen(argv, returncode=1)
                        elif mode == "failed_cleanup":
                            proc = _FakePopen(
                                argv,
                                expire_on_first_communicate=True,
                                expire_cleanup_communicate=True,
                                fail_cleanup_wait=True,
                            )
                        else:
                            proc = _FakePopen(argv, expire_on_first_communicate=True)
                        created.append(proc)
                        return proc

                    stopper = _FakeStopper(still_alive=still_alive)
                    stderr = io.StringIO()
                    with (
                        patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
                        redirect_stdout(io.StringIO()),
                        redirect_stderr(stderr),
                    ):
                        rc = run_watch(
                            self._args(),
                            config,
                            notifier=NotifySend(),
                            stopper=stopper,
                            now=lambda: stamp,
                        )

                    self.assertEqual(rc, expected_rc)
                    self.assertEqual(len(stopper.calls), 1)
                    self.assertEqual(stopper.calls[0][0].pids, (10, 11, 12, 13, 14))
                    self.assertEqual(stopper.calls[0][2], self.proc_root)
                    self.assertEqual(
                        load_ignored(self.ignored_file),
                        {expected_key: stamp + config.ignore_for_hours * 3600},
                    )
                    action_procs = [proc for proc in created if "--action=stop=Stop" in proc.argv]
                    inform_procs = [proc for proc in created if "--action=stop=Stop" not in proc.argv]
                    self.assertEqual(len(action_procs), 2)
                    if mode == "oserror":
                        self.assertEqual(inform_procs, [])
                        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                        self.assertIn("Warning:", stderr.getvalue())
                    else:
                        self.assertEqual(len(inform_procs), 1)
                        proc = inform_procs[0]
                        self.assertIn("stopped", proc.argv[-2])
                        _assert_positive_timeouts(self, proc.communicate_timeouts)
                        if mode == "timeout":
                            self.assertEqual(len(proc.communicate_timeouts), 2)
                            self.assertTrue(proc.killed)
                            self.assertTrue(proc.reaped)
                            self.assertEqual(proc.wait_timeouts, [])
                            self.assertEqual(stderr.getvalue(), "")
                        elif mode == "failed_cleanup":
                            self.assertEqual(len(proc.communicate_timeouts), 2)
                            self.assertTrue(proc.killed)
                            self.assertFalse(proc.reaped)
                            _assert_positive_timeouts(self, proc.wait_timeouts)
                            self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                            self.assertIn("Warning:", stderr.getvalue())
                        else:
                            self.assertEqual(len(proc.communicate_timeouts), 1)
                            self.assertFalse(proc.killed)
                            self.assertFalse(proc.reaped)
                            self.assertEqual(proc.wait_timeouts, [])
                            self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                            self.assertIn("Warning:", stderr.getvalue())

                    lock_path = self.state_dir / "watch.lock"
                    with lock_path.open("a", encoding="utf-8") as held:
                        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        self.assertFalse(held.closed)


class FormatTest(unittest.TestCase):
    def _finding(self, rss_kb: int, swap_kb: int = 0) -> Finding:
        return Finding(
            key="k",
            rule="idle-clones",
            owner_label="org.kde.yakuake",
            pids=(10, 11),
            rss_kb=rss_kb,
            swap_kb=swap_kb,
            reason="2 idle copies of bun start.mjs, running for at least 6 h",
        )

    def test_format_finding_and_notification_size(self) -> None:
        small = self._finding(1023 * 1024)
        large = self._finding(1024 * 1024)
        self.assertIn("1023 MB RAM", format_finding(small))
        self.assertIn("0 MB swap", format_finding(small))
        self.assertIn("1.0 GB RAM", format_finding(large))
        self.assertEqual(format_size(1023 * 1024), "1023 MB")
        self.assertEqual(format_size(1024 * 1024), "1.0 GB")
        small_summary, _ = _format_notification(small)
        large_summary, _ = _format_notification(large)
        self.assertEqual(small_summary, "org.kde.yakuake: 1023 MB in 2 processes")
        self.assertEqual(large_summary, "org.kde.yakuake: 1.0 GB in 2 processes")

    def test_notification_body_escapes_markup_in_label(self) -> None:
        finding = Finding(
            key="k",
            rule="other-user",
            owner_label="<b>x</b>",
            pids=(1,),
            rss_kb=1024,
            swap_kb=0,
            reason="held by <b>x</b>; information only, not stopped",
        )
        summary, body = _format_notification(finding)
        self.assertEqual(summary, "<b>x</b>: 1 MB in 1 processes")
        self.assertIn("&lt;b&gt;", body)
        self.assertNotIn("<", body)

    def test_label_starting_with_dash_is_never_parsed_as_an_option(self) -> None:
        finding = Finding(
            key="k",
            rule="other-user",
            owner_label="--icon=evil",
            pids=(1,),
            rss_kb=1024,
            swap_kb=0,
            reason="held by other; information only, not stopped",
        )
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, stdout_text="later\n")
            created.append(proc)
            return proc

        with patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen):
            NotifySend().ask([finding], 30)
            NotifySend().inform("--icon=evil: 1 process stopped", "body")

        for proc in created:
            separator = proc.argv.index("--")
            self.assertEqual(proc.argv[separator + 1].split(":")[0], "--icon=evil")
            self.assertEqual(len(proc.argv), separator + 3)

    def test_format_stop_result_sentences(self) -> None:
        self.assertEqual(
            format_stop_result(StopResult("k", "SIGTERM", (10, 11, 12, 13), (), ())),
            "4 processes stopped: 10, 11, 12, 13. Method: SIGTERM.",
        )
        self.assertEqual(
            format_stop_result(StopResult("k", "SIGTERM", (10,), (14, 15), ())),
            "1 process stopped: 10. Method: SIGTERM. Still running: 14, 15.",
        )
        self.assertEqual(
            format_stop_result(StopResult(
                "k", "rule: app stop", (), (), ((14, "pid reused"), (15, "not permitted")),
            )),
            "0 processes stopped. Method: rule: app stop. "
            "Skipped: 14 (pid reused), 15 (not permitted).",
        )


class NotifySendTest(unittest.TestCase):
    def _finding(self, key: str = "k1", pids: tuple[int, ...] = (10, 11)) -> Finding:
        return Finding(
            key=key,
            rule="idle-clones",
            owner_label="org.kde.yakuake",
            pids=pids,
            rss_kb=512 * 1024,
            swap_kb=256 * 1024,
            reason="2 idle copies of bun start.mjs, running for at least 6 h",
        )

    def test_ask_runs_notify_send_concurrently_and_maps_answers(self) -> None:
        f1 = self._finding("k1", (10, 11))
        f2 = self._finding("k2", (12, 13))
        f3 = self._finding("k3", (14, 15))
        created: list[_FakePopen] = []
        outputs = iter(["stop\n", "later\n", ""])

        def fake_popen(argv, *, stdout=None, text=None):
            self.assertEqual(stdout, -1)
            self.assertTrue(text)
            # Every Popen must be started before any communicate() call waits.
            self.assertTrue(all(not p.communicated for p in created))
            proc = _FakePopen(argv, stdout_text=next(outputs), returncode=0)
            created.append(proc)
            return proc

        with patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen):
            answers = NotifySend().ask([f1, f2, f3], 300)

        self.assertEqual(answers, {"k1": "stop", "k2": "later", "k3": ""})
        self.assertEqual(len(created), 3)
        argv = created[0].argv
        self.assertEqual(
            argv[:7],
            [
                "notify-send",
                "--app-name=ramCleaner",
                "--urgency=normal",
                "--expire-time=360000",
                "--action=stop=Stop",
                "--action=later=Later",
                "--action=hide=Hide...",
            ],
        )
        self.assertEqual(argv[7], "--")
        self.assertEqual(argv[8], "org.kde.yakuake: 768 MB in 2 processes")
        self.assertIn("2 idle copies of bun start.mjs, running for at least 6 h", argv[9])
        self.assertIn("10, 11", argv[9])

    def test_ask_uses_shared_deadline_and_kills_timed_out_process(self) -> None:
        f1 = self._finding("k1", (10, 11))
        f2 = self._finding("k2", (12, 13))
        f3 = self._finding("k3", (14, 15))
        specs = iter(
            [
                ("stop\n", False),
                ("", True),
                ("stop\n", False),
            ]
        )
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            stdout_text, expire = next(specs)
            proc = _FakePopen(
                argv,
                stdout_text=stdout_text,
                returncode=0,
                expire_on_first_communicate=expire,
            )
            created.append(proc)
            return proc

        # Start at 100.0 -> deadline = 700.0; p1 checked at 120.0 (580s left),
        # p2 checked at 350.0 (350s left, times out), p3 checked at 705.0 (0s left).
        ticks = iter([100.0, 120.0, 350.0, 705.0])
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            patch("ramcleaner.notify.time.monotonic", side_effect=lambda: next(ticks)),
        ):
            answers = NotifySend().ask([f1, f2, f3], 600)

        self.assertEqual(answers, {"k1": "stop", "k2": "timeout", "k3": "stop"})
        self.assertEqual(created[0].communicate_timeouts, [580.0])
        self.assertFalse(created[0].killed)
        self.assertEqual(created[1].communicate_timeouts, [350.0, None])
        self.assertTrue(created[1].killed)
        self.assertTrue(created[1].reaped)
        self.assertEqual(created[2].communicate_timeouts, [0.0])
        self.assertFalse(created[2].killed)

    def test_hide_passes_remaining_ask_time_to_zenity(self) -> None:
        finding = self._finding()
        seen: dict[str, object] = {}

        def fake_popen(argv, *, stdout=None, text=None):
            return _FakePopen(argv, stdout_text="hide\n")

        def runner(argv, timeout_s):
            seen["argv"] = list(argv)
            seen["timeout_s"] = timeout_s
            return subprocess.CompletedProcess(argv, 0, "6 hours\n", "")

        ticks = iter([100.0, 250.0, 400.0])
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            patch("ramcleaner.notify.time.monotonic", side_effect=lambda: next(ticks)),
        ):
            answers = NotifySend(dialog_runner=runner).ask([finding], 600)

        self.assertEqual(answers, {"k1": "6 hours"})
        self.assertEqual(seen["timeout_s"], 300.0)
        self.assertEqual(
            seen["argv"],
            [
                "zenity",
                "--forms",
                "--add-combo=Hide for",
                "--combo-values=1 hour|6 hours|24 hours|Until reboot",
                "--timeout=300",
            ],
        )

    def test_hide_dialog_without_a_display_falls_back_instead_of_cancelling(self) -> None:
        environ = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
        with (
            patch.dict(os.environ, environ, clear=True),
            patch("ramcleaner.notify.subprocess.Popen") as popen,
        ):
            token, warning = run_hide_dialog(5.0)

        popen.assert_not_called()
        self.assertEqual(token, "fallback")
        self.assertEqual(
            warning, "Warning: zenity unavailable, hiding for the default duration: no display"
        )

    def test_hide_dialog_does_not_start_when_under_one_second(self) -> None:
        def runner(argv, timeout_s):
            raise AssertionError("zenity started")

        self.assertEqual(run_hide_dialog(0.4, runner), ("timeout", None))

    def test_missing_zenity_warns_once_for_every_hide(self) -> None:
        findings = [self._finding("k1"), self._finding("k2")]

        def fake_popen(argv, *, stdout=None, text=None):
            return _FakePopen(argv, stdout_text="hide\n")

        def runner(argv, timeout_s):
            raise FileNotFoundError("no zenity")

        stderr = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            redirect_stderr(stderr),
        ):
            answers = NotifySend(dialog_runner=runner).ask(findings, 30)

        self.assertEqual(answers, {"k1": "fallback", "k2": "fallback"})
        self.assertEqual(
            stderr.getvalue().splitlines(),
            ["Warning: zenity unavailable, hiding for the default duration: no zenity"],
        )

    def test_hide_dialog_kills_zenity_when_the_ask_time_runs_out(self) -> None:
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, expire_on_first_communicate=True)
            created.append(proc)
            return proc

        with (
            patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-test"}),
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
        ):
            token, warning = run_hide_dialog(5.0)

        self.assertEqual((token, warning), ("timeout", None))
        self.assertEqual(len(created), 1)
        proc = created[0]
        self.assertEqual(proc.argv[-1], "--timeout=5")
        self.assertEqual(proc.communicate_timeouts[0], 5.0)
        self.assertTrue(proc.killed)
        self.assertTrue(proc.reaped)

    def test_missing_or_failing_notify_send_returns_unavailable_with_one_warning(self) -> None:
        findings = [self._finding("k1"), self._finding("k2")]

        stderr = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=FileNotFoundError("no notify-send")),
            redirect_stderr(stderr),
        ):
            answers = NotifySend().ask(findings, 600)
        self.assertEqual(answers, {"k1": "unavailable", "k2": "unavailable"})
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)

        stderr = io.StringIO()
        with (
            patch(
                "ramcleaner.notify.subprocess.Popen",
                side_effect=lambda argv, **kw: _FakePopen(argv, returncode=1),
            ),
            redirect_stderr(stderr),
        ):
            answers = NotifySend().ask(findings, 600)
        self.assertEqual(answers, {"k1": "unavailable", "k2": "unavailable"})
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)

    def test_inform_runs_without_actions(self) -> None:
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, returncode=0)
            created.append(proc)
            return proc

        with patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen):
            NotifySend().inform("Stopped yakuake", "method=SIGTERM  stopped=10")

        self.assertEqual(len(created), 1)
        self.assertEqual(
            created[0].argv,
            [
                "notify-send",
                "--app-name=ramCleaner",
                "--urgency=normal",
                "--",
                "Stopped yakuake",
                "method=SIGTERM  stopped=10",
            ],
        )

    def test_inform_timeout_kills_and_reaps_only_after_successful_cleanup(self) -> None:
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, expire_on_first_communicate=True)
            created.append(proc)
            return proc

        stderr = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            redirect_stderr(stderr),
        ):
            result = NotifySend().inform("Stopped yakuake", "method=SIGTERM")

        self.assertIsNone(result)
        self.assertEqual(len(created), 1)
        proc = created[0]
        self.assertEqual(len(proc.communicate_timeouts), 2)
        _assert_positive_timeouts(self, proc.communicate_timeouts)
        self.assertTrue(proc.killed)
        self.assertTrue(proc.reaped)
        self.assertEqual(proc.wait_timeouts, [])
        self.assertEqual(stderr.getvalue(), "")

    def test_inform_cleanup_timeout_waits_with_positive_timeout(self) -> None:
        for fail_wait, warning in ((False, False), (True, True)):
            with self.subTest(fail_wait=fail_wait):
                created: list[_FakePopen] = []

                def fake_popen(argv, *, stdout=None, text=None, created=created,
                               fail_wait=fail_wait):
                    proc = _FakePopen(
                        argv,
                        expire_on_first_communicate=True,
                        expire_cleanup_communicate=True,
                        fail_cleanup_wait=fail_wait,
                    )
                    created.append(proc)
                    return proc

                stderr = io.StringIO()
                with (
                    patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
                    redirect_stderr(stderr),
                ):
                    result = NotifySend().inform("Stopped yakuake", "method=SIGTERM")

                self.assertIsNone(result)
                self.assertEqual(len(created), 1)
                proc = created[0]
                self.assertEqual(len(proc.communicate_timeouts), 2)
                _assert_positive_timeouts(self, proc.communicate_timeouts)
                self.assertTrue(proc.killed)
                self.assertFalse(proc.reaped)
                self.assertEqual(len(proc.wait_timeouts), 1)
                _assert_positive_timeouts(self, proc.wait_timeouts)
                if warning:
                    self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                    self.assertIn("Warning:", stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")

    def test_inform_spawn_error_warns_once_and_returns(self) -> None:
        for exc_type in (OSError, FileNotFoundError):
            with self.subTest(exc_type=exc_type.__name__):
                stderr = io.StringIO()
                with (
                    patch(
                        "ramcleaner.notify.subprocess.Popen",
                        side_effect=exc_type("no notify-send"),
                    ),
                    redirect_stderr(stderr),
                ):
                    result = NotifySend().inform("Stopped yakuake", "method=SIGTERM")
                self.assertIsNone(result)
                self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                self.assertIn("Warning:", stderr.getvalue())

    def test_inform_nonzero_exit_warns_once_and_returns(self) -> None:
        created: list[_FakePopen] = []

        def fake_popen(argv, *, stdout=None, text=None):
            proc = _FakePopen(argv, returncode=1)
            created.append(proc)
            return proc

        stderr = io.StringIO()
        with (
            patch("ramcleaner.notify.subprocess.Popen", side_effect=fake_popen),
            redirect_stderr(stderr),
        ):
            result = NotifySend().inform("Stopped yakuake", "method=SIGTERM")

        self.assertIsNone(result)
        self.assertEqual(len(created), 1)
        proc = created[0]
        self.assertEqual(len(proc.communicate_timeouts), 1)
        _assert_positive_timeouts(self, proc.communicate_timeouts)
        self.assertFalse(proc.killed)
        self.assertFalse(proc.reaped)
        self.assertEqual(proc.wait_timeouts, [])
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertIn("Warning:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
