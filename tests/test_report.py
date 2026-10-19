# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ramcleaner.cli import main
from ramcleaner.procscan import scan_processes
from tests.fakeproc import build_tree


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.history = self.root / "state" / "ramcleaner" / "history.json"
        environment = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_STATE_HOME": str(self.root / "state"),
        })
        environment.start()
        self.addCleanup(environment.stop)

    def test_report_reference_incident(self) -> None:
        yakuake_cg = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.yakuake-850410.scope"
        )
        yakuake_tab_cg = f"{yakuake_cg}/tab(850422).scope"
        kwin_cg = (
            "/user.slice/user-1000.slice/user@1000.service/session.slice/"
            "plasma-kwin_wayland.service"
        )

        procs = [
            {
                "pid": 850410,
                "ppid": 1,
                "comm": "yakuake",
                "cmdline": ("/usr/bin/yakuake",),
                "rss_kb": 90000,
                "swap_kb": 0,
                "cgroup": yakuake_cg,
            },
            {
                "pid": 850500,
                "ppid": 1,
                "comm": "codex",
                "cmdline": ("codex", "app-server"),
                "rss_kb": 120000,
                "swap_kb": 40000,
                "cgroup": yakuake_tab_cg,
            },
            {
                "pid": 1200,
                "ppid": 1,
                "comm": "kwin_wayland",
                "cmdline": ("/usr/bin/kwin_wayland",),
                "rss_kb": 250000,
                "swap_kb": 0,
                "cgroup": kwin_cg,
            },
        ]
        for idx in range(5):
            procs.append(
                {
                    "pid": 851000 + idx,
                    "ppid": 850500,
                    "comm": "bun",
                    "cmdline": ("bun", "/opt/context-mode/start.mjs"),
                    "rss_kb": 600000,
                    "swap_kb": 600000,
                    "start_ticks": 100,
                    "cgroup": yakuake_tab_cg,
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            proc_root, cgroup_root = build_tree(
                tmp,
                procs,
                cgroups={
                    # The kernel charges the tab to the terminal's scope as well.
                    yakuake_cg: (1024**3 + 100 * 1024**2, 7 * 1024**3),
                    yakuake_tab_cg: (1024**3, 7 * 1024**3),
                    kwin_cg: (250 * 1024 * 1024, 0),
                },
            )
            tab_dir = cgroup_root / yakuake_tab_cg.lstrip("/")
            (tab_dir / "memory.current").write_text(str(7 * 1024**3), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(
                    [
                        "--proc-root",
                        str(proc_root),
                        "--cgroup-root",
                        str(cgroup_root),
                        "report",
                        "--interval",
                        "0",
                        "--top",
                        "5",
                    ]
                )
            self.assertEqual(rc, 0)
            lines = [line for line in buf.getvalue().splitlines() if line.strip()]
            self.assertEqual(lines[0], "RAM = anonymous memory, page cache excluded")
            top_row = lines[1]
            self.assertIn("org.kde.yakuake", top_row)
            self.assertIn("codex", top_row)
            self.assertIn("850500", top_row)
            self.assertIn("1024.0 MB RAM", top_row)
            self.assertIn("Findings:", lines)
            findings = [line for line in lines if line.startswith("idle-clones")]
            self.assertEqual(len(findings), 1)
            self.assertIn("org.kde.yakuake tab 850422", findings[0])
            self.assertIn("5 pids", findings[0])
            self.assertEqual(lines[-1], findings[0])
            self.assertFalse(self.history.parent.exists())
            result = subprocess.run(
                [sys.executable, "-B", "-m", "ramcleaner", "report", "--top", "3",
                 "--interval", "0", "--proc-root", str(proc_root),
                 "--cgroup-root", str(cgroup_root)],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout, buf.getvalue())
            self.assertFalse(self.history.parent.exists())

    def test_report_reads_history_without_writing_it(self) -> None:
        proc_root, cgroup_root = build_tree(
            self.root,
            [{"pid": 10, "ppid": 20, "state": "Z", "start_ticks": 100},
             {"pid": 20, "comm": "daemon", "rss_kb": 1000}],
        )
        history = self.root / "history.json"
        contents = json.dumps([{"time": 1000, "procs": {}, "zombies": ["10:100"]}])
        history.write_text(contents, encoding="utf-8")
        before = history.stat()
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch("ramcleaner.cli.time.sleep") as sleep:
            rc = main(["report", "--proc-root", str(proc_root),
                       "--cgroup-root", str(cgroup_root), "--interval", "0.25",
                       "--history-file", str(history)])
        self.assertEqual(rc, 0)
        sleep.assert_called_once_with(0.25)
        self.assertIn("zombie", stdout.getvalue())
        self.assertIn("Parent 20 (daemon) does not reap", stdout.getvalue())
        self.assertEqual(history.read_text(encoding="utf-8"), contents)
        after = history.stat()
        self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
        self.assertEqual(set(self.root.iterdir()), {proc_root, cgroup_root, history})

    def test_report_honors_protected_config_and_samples_twice(self) -> None:
        proc_root, cgroup_root = build_tree(
            self.root,
            [{"pid": pid, "comm": "bun", "rss_kb": 300000} for pid in range(10, 15)],
        )
        config_dir = self.root / "config" / "ramcleaner"
        config_dir.mkdir(parents=True)
        (config_dir / "config.toml").write_text('protected = ["bun"]\n', encoding="utf-8")
        with patch("ramcleaner.cli.scan_processes", wraps=scan_processes) as scan:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                main(["report", "--proc-root", str(proc_root),
                      "--cgroup-root", str(cgroup_root), "--interval", "0"])
        self.assertEqual(scan.call_count, 2)
        self.assertTrue(stdout.getvalue().endswith("Findings: none\n"))

    def test_report_default_interval(self) -> None:
        proc_root, cgroup_root = build_tree(self.root, [])
        with redirect_stdout(io.StringIO()), patch("ramcleaner.cli.time.sleep") as sleep:
            main(["report", "--proc-root", str(proc_root), "--cgroup-root", str(cgroup_root)])
        sleep.assert_called_once_with(2.0)

    def test_report_rejects_invalid_intervals_before_scanning(self) -> None:
        for interval in ("-1", "nan", "inf"):
            with self.subTest(interval=interval):
                with (
                    patch("ramcleaner.cli.scan_processes") as scan,
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as error,
                ):
                    main(["report", "--interval", interval])
                self.assertEqual(error.exception.code, 2)
                scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
