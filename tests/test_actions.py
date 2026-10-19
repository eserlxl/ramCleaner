# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import errno
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
        self.next_token = 100
        self.token_to_pid: dict[int, int] = {}
        self.opened_tokens: list[int] = []
        self.closed_tokens: list[int] = []

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

    def fake_pidfd_open(self, pid: int) -> int:
        pid_dir = self.proc_root / str(pid)
        if not pid_dir.exists():
            raise ProcessLookupError(pid)
        token = self.next_token
        self.next_token += 1
        self.token_to_pid[token] = pid
        self.opened_tokens.append(token)
        return token

    def fake_send_signal(self, token: int, sig: int) -> None:
        self.assertIn(token, self.token_to_pid)
        self.assertNotIn(token, self.closed_tokens)
        pid = self.token_to_pid[token]
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

    def fake_close(self, token: int) -> None:
        self.assertIn(token, self.token_to_pid)
        self.assertNotIn(token, self.closed_tokens)
        self.closed_tokens.append(token)

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
            pidfd_open=self.fake_pidfd_open,
            send_signal=self.fake_send_signal,
            close=self.fake_close,
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

    def test_reused_after_pidfd_open_is_skipped_and_never_signaled(self) -> None:
        def open_then_reuse_10(pid: int) -> int:
            token = self.fake_pidfd_open(pid)
            if pid == 10:
                write_proc(self.proc_root, {**self.specs[0], "start_ticks": 999})
            return token

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            pidfd_open=open_then_reuse_10,
            send_signal=self.fake_send_signal,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.stopped, (11,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((10, "pid reused"),))
        self.assertEqual(self.signals, [(11, signal.SIGTERM)])
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

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
            proc_root=self.proc_root,
            pidfd_open=self.fake_pidfd_open,
            send_signal=self.fake_send_signal,
            close=self.fake_close,
            run=missing_command,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
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
        def denied_for_11(token: int, sig: int) -> None:
            if self.token_to_pid[token] == 11:
                raise PermissionError(1, "Operation not permitted")
            self.fake_send_signal(token, sig)

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            pidfd_open=self.fake_pidfd_open,
            send_signal=denied_for_11,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.stopped, (10,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((11, "not permitted"),))

    def test_pidfd_open_enosys_skips_as_unavailable_without_signaling(self) -> None:
        def unavailable(pid: int) -> int:
            raise OSError(errno.ENOSYS, "Function not implemented")

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            pidfd_open=unavailable,
            send_signal=self.fake_send_signal,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.stopped, ())
        self.assertEqual(result.still_alive, ())
        self.assertEqual(
            result.skipped,
            ((10, "pidfd unavailable"), (11, "pidfd unavailable")),
        )
        self.assertEqual(self.signals, [])
        self.assertEqual(self.opened_tokens, [])
        self.assertEqual(self.closed_tokens, [])

    def test_every_opened_token_is_closed_on_all_paths(self) -> None:
        def reset_procs() -> None:
            for spec in self.specs:
                write_proc(self.proc_root, spec)
            self.opened_tokens.clear()
            self.closed_tokens.clear()
            self.ignore_sigterm.clear()

        # SIGTERM path
        reset_procs()
        self.stop()
        self.assertEqual(len(self.opened_tokens), 2)
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

        # force path
        reset_procs()
        self.ignore_sigterm.add(11)
        self.stop(force=True)
        self.assertEqual(len(self.opened_tokens), 2)
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

        # rule path
        reset_procs()
        self.stop(config=Config(stop_rules=(("start\\.mjs", "codex stop"),)))
        self.assertEqual(len(self.opened_tokens), 2)
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

        # all-skipped path
        reset_procs()
        self.stop(config=Config(protected=("bun",)))
        self.assertEqual(len(self.opened_tokens), 2)
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

        # unexpected OSError from send_signal
        reset_procs()

        def failing_send_signal(token: int, sig: int) -> None:
            raise OSError(errno.EINVAL, "Invalid argument")

        with self.assertRaises(OSError):
            stop_finding(
                self.finding,
                Config(term_timeout=1),
                proc_root=self.proc_root,
                pidfd_open=self.fake_pidfd_open,
                send_signal=failing_send_signal,
                close=self.fake_close,
                run=self.fake_run,
                sleep=self.fake_sleep,
                monotonic=self.fake_monotonic,
            )
        self.assertEqual(len(self.opened_tokens), 2)
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

    def test_zombie_counts_as_exited(self) -> None:
        self.zombie_on_sigterm.add(10)
        result = self.stop()
        self.assertEqual(result.stopped, (10, 11))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ())

    def _assert_stop_partition(self, result: StopResult) -> None:
        skipped_pids = {pid for pid, _reason in result.skipped}
        self.assertTrue(set(result.stopped).isdisjoint(result.still_alive))
        self.assertTrue(set(result.stopped).isdisjoint(skipped_pids))
        self.assertTrue(set(result.still_alive).isdisjoint(skipped_pids))
        self.assertEqual(sorted(self.closed_tokens), sorted(self.opened_tokens))

    def test_force_skips_cmdline_change_as_pid_reused(self) -> None:
        self.ignore_sigterm.update({10, 11})

        def send(token: int, sig: int) -> None:
            self.fake_send_signal(token, sig)
            if sig == signal.SIGTERM and self.token_to_pid[token] == 10:
                write_proc(self.proc_root, {**self.specs[0], "cmdline": ("/bin/other",)})

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            force=True,
            pidfd_open=self.fake_pidfd_open,
            send_signal=send,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.method, "SIGTERM+SIGKILL")
        self.assertEqual(result.stopped, (11,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((10, "pid reused"),))
        self.assertEqual(
            self.signals,
            [
                (10, signal.SIGTERM),
                (11, signal.SIGTERM),
                (11, signal.SIGKILL),
            ],
        )
        self._assert_stop_partition(result)

    def test_force_skips_comm_that_became_protected(self) -> None:
        self.ignore_sigterm.update({10, 11})

        def send(token: int, sig: int) -> None:
            self.fake_send_signal(token, sig)
            if sig == signal.SIGTERM and self.token_to_pid[token] == 10:
                write_proc(self.proc_root, {**self.specs[0], "comm": "kwin_wayland"})

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            force=True,
            pidfd_open=self.fake_pidfd_open,
            send_signal=send,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.stopped, (11,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((10, "protected"),))
        self.assertNotIn((10, signal.SIGKILL), self.signals)
        self.assertIn((11, signal.SIGKILL), self.signals)
        self._assert_stop_partition(result)

    def test_force_sigkill_permission_denied_skips_and_continues(self) -> None:
        self.ignore_sigterm.update({10, 11})

        def send(token: int, sig: int) -> None:
            if sig == signal.SIGKILL and self.token_to_pid[token] == 10:
                raise PermissionError(1, "Operation not permitted")
            self.fake_send_signal(token, sig)

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            force=True,
            pidfd_open=self.fake_pidfd_open,
            send_signal=send,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.method, "SIGTERM+SIGKILL")
        self.assertEqual(result.stopped, (11,))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ((10, "not permitted"),))
        self.assertEqual(
            self.signals,
            [
                (10, signal.SIGTERM),
                (11, signal.SIGTERM),
                (11, signal.SIGKILL),
            ],
        )
        self._assert_stop_partition(result)

    def test_force_start_ticks_change_during_wait_stays_stopped(self) -> None:
        self.ignore_sigterm.update({10, 11})

        def send(token: int, sig: int) -> None:
            self.fake_send_signal(token, sig)
            if sig == signal.SIGTERM and self.token_to_pid[token] == 10:
                write_proc(self.proc_root, {**self.specs[0], "start_ticks": 999})

        result = stop_finding(
            self.finding,
            Config(term_timeout=1),
            proc_root=self.proc_root,
            force=True,
            pidfd_open=self.fake_pidfd_open,
            send_signal=send,
            close=self.fake_close,
            run=self.fake_run,
            sleep=self.fake_sleep,
            monotonic=self.fake_monotonic,
        )
        self.assertEqual(result.method, "SIGTERM+SIGKILL")
        self.assertEqual(result.stopped, (10, 11))
        self.assertEqual(result.still_alive, ())
        self.assertEqual(result.skipped, ())
        self.assertNotIn((10, signal.SIGKILL), self.signals)
        self.assertIn((11, signal.SIGKILL), self.signals)
        self._assert_stop_partition(result)


if __name__ == "__main__":
    unittest.main()
