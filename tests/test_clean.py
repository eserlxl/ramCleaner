# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ramcleaner.actions import StopResult
from ramcleaner.cli import main
from tests.fakeproc import build_tree


class CleanTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = patch.dict(
            os.environ,
            {
                "XDG_CONFIG_HOME": str(self.root / "config"),
                "XDG_STATE_HOME": str(self.root / "state"),
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

        self.proc_root, self.cgroup_root = build_tree(
            self.root,
            [
                {
                    "pid": pid,
                    "ppid": 20,
                    "comm": "bun",
                    "cmdline": ("bun", "/opt/context-mode/start.mjs"),
                    "rss_kb": 300 * 1024,
                    "swap_kb": 100 * 1024,
                    "start_ticks": 100,
                }
                for pid in range(10, 15)
            ],
        )

    def test_non_tty_exits_2_without_scanning(self) -> None:
        stderr = io.StringIO()
        with (
            patch("ramcleaner.cli.sys.stdin.isatty", return_value=False),
            patch("ramcleaner.cli.scan_processes") as scan,
            redirect_stderr(stderr),
        ):
            rc = main(
                [
                    "clean",
                    "--interval",
                    "0",
                    "--proc-root",
                    str(self.proc_root),
                    "--cgroup-root",
                    str(self.cgroup_root),
                ]
            )
        self.assertEqual(rc, 2)
        self.assertIn(
            "clean needs an interactive terminal; ramcleaner watch sends notifications",
            stderr.getvalue(),
        )
        scan.assert_not_called()

    def test_no_findings_prints_none_and_exits_0(self) -> None:
        empty_proc, empty_cg = build_tree(self.root / "empty", [])
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.sys.stdin.isatty", return_value=True),
            patch("builtins.input") as mock_input,
            patch("ramcleaner.cli.stop_finding") as mock_stop,
            redirect_stdout(stdout),
        ):
            rc = main(
                [
                    "clean",
                    "--interval",
                    "0",
                    "--proc-root",
                    str(empty_proc),
                    "--cgroup-root",
                    str(empty_cg),
                ]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().strip(), "Findings: none")
        mock_input.assert_not_called()
        mock_stop.assert_not_called()

    def test_approve_stops_finding_and_prints_summary(self) -> None:
        for answer, force in (("y", False), ("YES", True)):
            with self.subTest(answer=answer, force=force):
                stdout = io.StringIO()
                fake_result = StopResult(
                    finding_key="idle-clones",
                    method="SIGTERM+SIGKILL" if force else "SIGTERM",
                    stopped=(10, 11, 12, 13),
                    still_alive=(),
                    skipped=((14, "pid reused"),),
                )
                argv = [
                    "clean",
                    "--interval",
                    "0",
                    "--proc-root",
                    str(self.proc_root),
                    "--cgroup-root",
                    str(self.cgroup_root),
                ]
                if force:
                    argv.append("--force")
                with (
                    patch("ramcleaner.cli.sys.stdin.isatty", return_value=True),
                    patch("builtins.input", return_value=answer) as mock_input,
                    patch("ramcleaner.cli.stop_finding", return_value=fake_result) as mock_stop,
                    redirect_stdout(stdout),
                ):
                    rc = main(argv)
                self.assertEqual(rc, 0)
                mock_input.assert_called_once_with("Stop it? [y/N] ")
                self.assertEqual(mock_stop.call_count, 1)
                self.assertEqual(mock_stop.call_args.kwargs["force"], force)
                output = stdout.getvalue()
                self.assertIn("idle-clones", output)
                self.assertIn(fake_result.method, output)
                self.assertIn("10, 11, 12, 13", output)
                self.assertIn("14 (pid reused)", output)

    def test_decline_or_eof_does_not_stop(self) -> None:
        for side_effect in (["n"], [""], ["no"], EOFError):
            with self.subTest(side_effect=side_effect):
                stdout = io.StringIO()
                with (
                    patch("ramcleaner.cli.sys.stdin.isatty", return_value=True),
                    patch("builtins.input", side_effect=side_effect),
                    patch("ramcleaner.cli.stop_finding") as mock_stop,
                    redirect_stdout(stdout),
                ):
                    rc = main(
                        [
                            "clean",
                            "--interval",
                            "0",
                            "--proc-root",
                            str(self.proc_root),
                            "--cgroup-root",
                            str(self.cgroup_root),
                        ]
                    )
                self.assertEqual(rc, 0)
                mock_stop.assert_not_called()

    def test_survivors_exit_1(self) -> None:
        stdout = io.StringIO()
        fake_result = StopResult(
            finding_key="idle-clones",
            method="SIGTERM",
            stopped=(10, 11, 12, 13),
            still_alive=(14,),
            skipped=(),
        )
        with (
            patch("ramcleaner.cli.sys.stdin.isatty", return_value=True),
            patch("builtins.input", return_value="y"),
            patch("ramcleaner.cli.stop_finding", return_value=fake_result) as mock_stop,
            redirect_stdout(stdout),
        ):
            rc = main(
                [
                    "clean",
                    "--interval",
                    "0",
                    "--proc-root",
                    str(self.proc_root),
                    "--cgroup-root",
                    str(self.cgroup_root),
                ]
            )
        self.assertEqual(rc, 1)
        mock_stop.assert_called_once()
        self.assertIn("14", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
