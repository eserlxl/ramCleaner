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
from pathlib import Path
from unittest.mock import patch

from ramcleaner.actions import StopResult
from ramcleaner.cli import main
from ramcleaner.config import Config
from ramcleaner.detect import Finding
from ramcleaner.history import load_history
from ramcleaner.notify import NotifySend
from ramcleaner.watch import load_ignored, run_watch
from tests.fakeproc import build_tree


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
    ) -> None:
        self.argv = argv
        self._stdout_text = stdout_text
        self.returncode = returncode
        self._expire_on_first = expire_on_first_communicate
        self.communicated = False
        self.communicate_timeouts: list[float | None] = []
        self.killed = False
        self.reaped = False

    def kill(self) -> None:
        self.killed = True

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self.communicated = True
        self.communicate_timeouts.append(timeout)
        if self._expire_on_first:
            self._expire_on_first = False
            raise subprocess.TimeoutExpired(self.argv, timeout or 0.0)
        if self.killed:
            self.reaped = True
        return self._stdout_text, ""


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

    def test_suppression_window_and_expiry_pruning(self) -> None:
        config = Config(ignore_for_hours=2)
        for outcome in ("ignore", "", "unavailable"):
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
                self.assertIn("method=SIGTERM", body)
                self.assertIn("stopped=10, 11, 12, 13", body)
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


class NotifySendTest(unittest.TestCase):
    def _finding(self, key: str = "k1", pids: tuple[int, ...] = (10, 11)) -> Finding:
        return Finding(
            key=key,
            rule="idle-clones",
            owner_label="org.kde.yakuake",
            pids=pids,
            rss_kb=512 * 1024,
            swap_kb=256 * 1024,
            reason="2 idle copies of bun start.mjs older than 6 h",
        )

    def test_ask_runs_notify_send_concurrently_and_maps_answers(self) -> None:
        f1 = self._finding("k1", (10, 11))
        f2 = self._finding("k2", (12, 13))
        f3 = self._finding("k3", (14, 15))
        created: list[_FakePopen] = []
        outputs = iter(["stop\n", "ignore\n", ""])

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

        self.assertEqual(answers, {"k1": "stop", "k2": "ignore", "k3": ""})
        self.assertEqual(len(created), 3)
        argv = created[0].argv
        self.assertEqual(
            argv[:6],
            [
                "notify-send",
                "--app-name=ramCleaner",
                "--urgency=normal",
                "--expire-time=360000",
                "--action=stop=Stop",
                "--action=ignore=Ignore",
            ],
        )
        self.assertEqual(argv[6], "org.kde.yakuake: 768 MB in 2 processes")
        self.assertIn("2 idle copies of bun start.mjs older than 6 h", argv[7])
        self.assertIn("10, 11", argv[7])

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
                "Stopped yakuake",
                "method=SIGTERM  stopped=10",
            ],
        )


if __name__ == "__main__":
    unittest.main()
