# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import shutil
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ramcleaner.actions import StopResult, stop_finding
from ramcleaner.config import Config
from ramcleaner.detect import Finding
from ramcleaner.procscan import scan_processes
from tests.fakeproc import build_tree, write_proc


class ActionsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.specs = [
            {
                "pid": pid,
                "ppid": 20,
                "comm": "bun",
                "cmdline": ("/usr/bin/bun", "/opt/context-mode/start.mjs"),
                "rss_kb": 256 * 1024,
                "swap_kb": 64 * 1024,
                "start_ticks": 100,
            }
            for pid in (10, 11)
        ]
        self.proc_root, _ = build_tree(self.root, self.specs)
        self.procs = scan_processes(self.proc_root)
        self.finding = Finding(
            key="idle-clones:/app.slice/app.scope:('bun', '/opt/context-mode/start.mjs')",
            rule="idle-clones",
            owner_label="app",
            pids=(10, 11),
            rss_kb=512 * 1024,
            swap_kb=128 * 1024,
            reason="2 idle copies",
            procs=(self.procs[10], self.procs[11]),
        )
        self.now = 0.0
        self.sleeps: list[float] = []
        self.signals: list[tuple[int, int]] = []
        self.runs: list[tuple[list[str], bool, int]] = []
        self.ignore_sigterm: set[int] = set()
        self.zombie_on_sigterm: set[int] = set()

        for target, value in (
            ("ramcleaner.detect.os.getpid", 9000),
            ("ramcleaner.detect.os.getppid", 9001),
        ):
            mock = patch(target, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def fake_monotonic(self) -> float:
        return self.now

    def fake_sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def fake_kill(self, pid: int, sig: int) -> None:
        self.signals.append((pid, sig))
        pid_dir = self.proc_root / str(pid)
        if not pid_dir.exists():
            raise ProcessLookupError(pid)
        if sig == signal.SIGKILL:
            shutil.rmtree(pid_dir)
        elif sig == signal.SIGTERM:
            if pid in self.zombie_on_sigterm:
                spec = next(item for item in self.specs if item["pid"] == pid)
                write_proc(self.proc_root, {**spec, "state": "Z"})
            elif pid not in self.ignore_sigterm:
                shutil.rmtree(pid_dir)

    def fake_run(
        self,
        argv: list[str],
        *,
        check: bool = False,
        timeout: int = 60,
    ) -> None:
        self.runs.append((argv, check, timeout))
        for pid in self.finding.pids:
            pid_dir = self.proc_root / str(pid)
            if pid_dir.exists():
                shutil.rmtree(pid_dir)

    def stop(
        self,
        finding: Finding | None = None,
        config: Config | None = None,
        *,
        force: bool = False,
    ) -> StopResult:
        return stop_finding(
            finding or self.finding,
            config or Config(term_timeout=1),
            proc_root=self.proc_root,
            force=force,
            kill=self.fake_kill,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )

    def test_sigterm_stops_processes(self) -> None:
        result = self.stop()
        self.assertEqual(
            result,
            StopResult(
                finding_key=self.finding.key,
                method="SIGTERM",
                stopped=(10, 11),
                still_alive=(),
                skipped=(),
            ),
        )
        self.assertEqual(
            self.signals,
            [(10, signal.SIGTERM), (11, signal.SIGTERM)],
        )
        self.assertEqual(self.runs, [])

    def test_ignoring_sigterm_stays_alive_without_force_and_stops_with_force(self) -> None:
        self.ignore_sigterm.add(11)
        without_force = self.stop(config=Config(term_timeout=1), force=False)
        self.assertEqual(without_force.method, "SIGTERM")
        self.assertEqual(without_force.stopped, (10,))
        self.assertEqual(without_force.still_alive, (11,))
        self.assertEqual(without_force.skipped, ())
        self.assertEqual(
            self.signals,
            [(10, signal.SIGTERM), (11, signal.SIGTERM)],
        )
        self.assertGreaterEqual(self.now, 1.0)

        write_proc(self.proc_root, self.specs[0])
        self.signals.clear()
        self.sleeps.clear()
        self.now = 0.0
        with_force = self.stop(config=Config(term_timeout=1), force=True)
        self.assertEqual(with_force.method, "SIGTERM+SIGKILL")
        self.assertEqual(with_force.stopped, (10, 11))
        self.assertEqual(with_force.still_alive, ())
        self.assertEqual(
            self.signals,
            [
                (10, signal.SIGTERM),
                (11, signal.SIGTERM),
                (11, signal.SIGKILL),
            ],
        )

    def test_reused_or_gone_pid_is_skipped_and_never_signaled(self) -> None:
        write_proc(self.proc_root, {**self.specs[0], "start_ticks": 999})
        result = self.stop()
        self.assertEqual(result.stopped, (11,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((10, "pid reused"),))
        self.assertEqual(self.signals, [(11, signal.SIGTERM)])

        self.signals.clear()
        write_proc(self.proc_root, {**self.specs[0], "cmdline": ("/bin/other",)})
        result_gone = self.stop()
        self.assertEqual(
            result_gone.skipped,
            ((10, "pid reused"), (11, "gone")),
        )
        self.assertEqual(self.signals, [])

    def test_protected_comm_is_skipped(self) -> None:
        write_proc(self.proc_root, {**self.specs[0], "comm": "kwin_wayland"})
        result = self.stop(config=Config(protected=("bun",)))
        self.assertEqual(result.stopped, ())
        self.assertEqual(result.still_alive, ())
        self.assertEqual(
            result.skipped,
            ((10, "protected"), (11, "protected")),
        )
        self.assertEqual(self.signals, [])
        self.assertEqual(self.runs, [])

    def test_matching_stop_rule_runs_split_argv_without_signaling(self) -> None:
        config = Config(
            stop_rules=(
                ("nonmatching", "ignore this"),
                ("context-mode/start\\.mjs", "codex app-server daemon stop"),
            )
        )
        result = self.stop(config=config)
        self.assertEqual(result.method, "rule: codex app-server daemon stop")
        self.assertEqual(result.stopped, (10, 11))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ())
        self.assertEqual(
            self.runs,
            [(["codex", "app-server", "daemon", "stop"], False, 60)],
        )
        self.assertEqual(self.signals, [])

    def test_failing_stop_rule_reports_survivors_without_raising(self) -> None:
        def missing_command(argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        result = stop_finding(
            self.finding,
            Config(term_timeout=1, stop_rules=(("start\\.mjs", "no-such-stopper"),)),
            proc_root=self.proc_root, kill=self.fake_kill, run=missing_command,
            sleep=self.fake_sleep, monotonic=self.fake_monotonic,
        )
        self.assertTrue(result.method.startswith("rule failed: no-such-stopper"))
        self.assertEqual(result.still_alive, (10, 11))
        self.assertEqual(self.signals, [])

    def test_pid_missing_from_scan_is_never_signaled(self) -> None:
        finding = Finding(**{**self.finding.__dict__, "procs": (self.procs[10],)})
        result = self.stop(finding)
        self.assertEqual(result.skipped, ((11, "not in scan"),))
        self.assertEqual(self.signals, [(10, signal.SIGTERM)])

    def test_permission_denied_is_skipped_not_raised(self) -> None:
        def denied_for_11(pid: int, sig: int) -> None:
            if pid == 11:
                raise PermissionError(1, "Operation not permitted")
            self.fake_kill(pid, sig)

        result = stop_finding(
            self.finding, Config(term_timeout=1), proc_root=self.proc_root,
            kill=denied_for_11, run=self.fake_run,
            sleep=self.fake_sleep, monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.stopped, (10,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((11, "not permitted"),))

    def test_zombie_counts_as_exited(self) -> None:
        self.zombie_on_sigterm.add(10)
        result = self.stop()
        self.assertEqual(result.stopped, (10, 11))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ())


if __name__ == "__main__":
    unittest.main()
