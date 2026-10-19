# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout

from ramcleaner.cli import main
from tests.fakeproc import build_tree


class ReportTest(unittest.TestCase):
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
                    "cgroup": yakuake_tab_cg,
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            proc_root, cgroup_root = build_tree(
                tmp,
                procs,
                cgroups={
                    # The kernel charges the tab to the terminal's scope as well.
                    yakuake_cg: (7 * 1024**3 + 100 * 1024**2, 7 * 1024**3),
                    yakuake_tab_cg: (7 * 1024**3, 7 * 1024**3),
                    kwin_cg: (250 * 1024 * 1024, 0),
                },
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(
                    [
                        "--proc-root",
                        str(proc_root),
                        "--cgroup-root",
                        str(cgroup_root),
                        "report",
                        "--top",
                        "5",
                    ]
                )
            self.assertEqual(rc, 0)
            lines = [line for line in buf.getvalue().splitlines() if line.strip()]
            self.assertGreaterEqual(len(lines), 2)
            top_row = lines[0]
            self.assertIn("org.kde.yakuake", top_row)
            self.assertIn("codex", top_row)
            self.assertIn("850500", top_row)


if __name__ == "__main__":
    unittest.main()
