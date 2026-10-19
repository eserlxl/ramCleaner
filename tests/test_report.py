# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ramcleaner
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
            self.assertEqual(
                result.stderr,
                "Note: 0 of 4 watch scans in the last 24 h; growth checks need 4 and zombie checks need 1, recorded by the ramcleaner-watch timer\n",
            )
            self.assertEqual(result.stdout, buf.getvalue())
            self.assertFalse(self.history.parent.exists())

    def test_report_reads_history_without_writing_it(self) -> None:
        proc_root, cgroup_root = build_tree(
            self.root,
            [{"pid": 10, "ppid": 20, "state": "Z", "start_ticks": 100},
             {"pid": 20, "comm": "daemon", "rss_kb": 1000}],
        )
        history = self.root / "history.json"
        contents = json.dumps([
            {"time": 1000, "procs": {}, "zombies": ["10:100"], "boot_id": "boot-fixture"},
        ])
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

    def test_version_prints_package_version_without_scanning(self) -> None:
        stdout = io.StringIO()
        with (
            patch("ramcleaner.cli.scan_processes") as scan,
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as error,
        ):
            main(["--version"])
        self.assertEqual(error.exception.code, 0)
        self.assertEqual(stdout.getvalue(), f"ramcleaner {ramcleaner.__version__}\n")
        scan.assert_not_called()

    def test_history_file_help_states_what_each_subcommand_does_with_it(self) -> None:
        docs = " ".join((Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md")
                        .read_text(encoding="utf-8").split())
        for command, phrase in (
            ("report", "History file to read (default: XDG state directory)."),
            ("watch", "History file to read and append each scan to"),
            ("ignored", "History file whose directory holds ignored.json and watch.lock"),
        ):
            with self.subTest(command=command):
                stdout = io.StringIO()
                with redirect_stdout(stdout), self.assertRaises(SystemExit):
                    main([command, "--help"])
                self.assertIn(phrase, " ".join(stdout.getvalue().split()))
                self.assertIn(phrase, docs)

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

    def test_report_rejects_invalid_config_before_scanning(self) -> None:
        config_file = self.root / "config" / "ramcleaner" / "config.toml"
        config_file.parent.mkdir(parents=True)
        for text, key in (
            ("bogus = 1\n", "bogus"),
            ("history_hours = 0\n", "history_hours"),
            ('stop_rules = [["(", "true"]]\n', "stop_rules"),
        ):
            with self.subTest(key=key):
                config_file.write_text(text, encoding="utf-8")
                stderr = io.StringIO()
                with (
                    patch("ramcleaner.cli.scan_processes") as scan,
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as error,
                ):
                    main(["report"])
                self.assertEqual(error.exception.code, 2)
                self.assertIn(key, stderr.getvalue())
                scan.assert_not_called()

    def test_report_shows_zswap_suffix_only_when_present(self) -> None:
        yakuake_cg = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.yakuake-850410.scope"
        )
        yakuake_tab_cg = f"{yakuake_cg}/tab(850422).scope"
        kwin_cg = (
            "/user.slice/user-1000.slice/user@1000.service/session.slice/"
            "plasma-kwin_wayland.service"
        )
        proc_root, cgroup_root = build_tree(
            self.root,
            [
                {
                    "pid": 850410,
                    "ppid": 1,
                    "comm": "yakuake",
                    "rss_kb": 90000,
                    "swap_kb": 0,
                    "cgroup": yakuake_cg,
                },
                {
                    "pid": 850500,
                    "ppid": 1,
                    "comm": "codex",
                    "rss_kb": 120000,
                    "swap_kb": 40000,
                    "cgroup": yakuake_tab_cg,
                },
                {
                    "pid": 1200,
                    "ppid": 1,
                    "comm": "kwin_wayland",
                    "rss_kb": 250000,
                    "swap_kb": 0,
                    "cgroup": kwin_cg,
                },
            ],
            cgroups={
                yakuake_cg: (1100 * 1024**2, 700 * 1024**2, 150 * 1024**2),
                yakuake_tab_cg: (1000 * 1024**2, 700 * 1024**2, 150 * 1024**2),
                kwin_cg: (250 * 1024**2, 0),
            },
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main(
                [
                    "report",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--interval",
                    "0",
                ]
            )
        self.assertEqual(rc, 0)
        rows = stdout.getvalue().splitlines()[1:4]
        self.assertTrue(rows[0].startswith("org.kde.yakuake tab 850422"))
        self.assertTrue(rows[0].endswith("  1000.0 MB RAM    700.0 MB swap    150.0 MB in zswap"))
        for row in rows[1:]:
            self.assertNotIn("zswap", row)

    def test_report_marks_rows_without_cgroup_memory(self) -> None:
        readable_cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo-1.scope"
        unreadable_cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-bar-2.scope"
        proc_root, cgroup_root = build_tree(
            self.root,
            [
                {"pid": 100, "ppid": 1, "comm": "foo", "rss_kb": 400000, "cgroup": readable_cg},
                {"pid": 200, "ppid": 1, "comm": "bar", "rss_kb": 300000, "cgroup": unreadable_cg},
            ],
            cgroups={readable_cg: (500 * 1024**2, 0)},
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main([
                "report", "--proc-root", str(proc_root), "--cgroup-root", str(cgroup_root),
                "--interval", "0",
            ])
        self.assertEqual(rc, 0)
        rows = stdout.getvalue().splitlines()[1:3]
        self.assertTrue(rows[0].startswith("foo"))
        self.assertNotIn("VmRSS", rows[0])
        self.assertTrue(rows[1].startswith("bar"))
        self.assertTrue(rows[1].endswith("  (VmRSS: cgroup memory unreadable)"))

    def test_report_marks_only_unreadable_mixed_hierarchy_rows(self) -> None:
        parent = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.konsole-2469.scope"
        )
        child = f"{parent}/tab(20).scope"
        grandchild = f"{child}/tab(21).scope"
        mib = 1024**2
        proc_root, cgroup_root = build_tree(
            self.root,
            [
                {"pid": 10, "ppid": 1, "comm": "konsole", "rss_kb": 1, "swap_kb": 0,
                 "cgroup": parent},
                {"pid": 20, "ppid": 10, "comm": "bash", "rss_kb": 500 * 1024,
                 "swap_kb": 250 * 1024, "cgroup": child},
                {"pid": 21, "ppid": 20, "comm": "agent", "rss_kb": 1, "swap_kb": 0,
                 "cgroup": grandchild},
            ],
            cgroups={
                parent: (1000 * mib, 500 * mib, 200 * mib),
                grandchild: (300 * mib, 150 * mib, 60 * mib),
            },
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main([
                "report", "--proc-root", str(proc_root), "--cgroup-root", str(cgroup_root),
                "--interval", "0",
            ])
        self.assertEqual(rc, 0)
        rows = stdout.getvalue().splitlines()[1:4]
        marker = "  (VmRSS: cgroup memory unreadable)"
        self.assertTrue(rows[0].startswith("org.kde.konsole tab 20"))
        self.assertTrue(rows[0].endswith(marker))
        self.assertNotIn("zswap", rows[0])
        self.assertTrue(rows[1].startswith("org.kde.konsole tab 21"))
        self.assertNotIn(marker, rows[1])
        self.assertIn("in zswap", rows[1])
        self.assertTrue(rows[2].startswith("org.kde.konsole  "))
        self.assertNotIn(marker, rows[2])
        self.assertIn("in zswap", rows[2])

    def test_report_history_note_when_scans_under_four(self) -> None:
        proc_root, cgroup_root = build_tree(self.root, [])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(
                [
                    "report",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--interval",
                    "0",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(
            stderr.getvalue(),
            "Note: 0 of 4 watch scans in the last 24 h; growth checks need 4 and zombie checks need 1, recorded by the ramcleaner-watch timer\n",
        )

        now = time.time()
        self.history.parent.mkdir(parents=True, exist_ok=True)
        # Scans from another boot cannot feed detection, so they must not hide the note.
        for boot_id, expected in (
            ("other-boot", (
                "Note: 0 of 4 watch scans in the last 24 h; growth checks need 4 "
                "and zombie checks need 1, recorded by the ramcleaner-watch timer\n"
            )),
            ("boot-fixture", ""),
        ):
            with self.subTest(boot_id=boot_id):
                entries = [
                    {"time": now - idx * 60, "procs": {}, "zombies": [], "boot_id": boot_id}
                    for idx in range(4)
                ]
                self.history.write_text(json.dumps(entries), encoding="utf-8")

                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = main(
                        [
                            "report",
                            "--proc-root",
                            str(proc_root),
                            "--cgroup-root",
                            str(cgroup_root),
                            "--interval",
                            "0",
                        ]
                    )
                self.assertEqual(rc, 0)
                self.assertEqual(stderr.getvalue(), expected)


if __name__ == "__main__":
    unittest.main()
