# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from ramcleaner.procscan import (
    clock_ticks,
    read_cgroup_memory,
    read_uptime,
    scan_processes,
)
from tests.fakeproc import build_tree


class ProcscanTest(unittest.TestCase):
    def test_comm_with_spaces_and_parens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root, _ = build_tree(
                tmp,
                [
                    {
                        "pid": 42,
                        "ppid": 1,
                        "state": "R",
                        "comm": "Web Content (1) test",
                        "cmdline": ("/usr/lib/firefox/firefox", "-contentproc"),
                        "uid": 1000,
                        "rss_kb": 204800,
                        "swap_kb": 10240,
                        "utime": 120,
                        "stime": 30,
                        "start_ticks": 98765,
                        "cgroup": "/user.slice/user-1000.slice/app.slice/app-firefox-1.scope",
                    }
                ],
            )
            procs = scan_processes(proc_root=proc_root, uid=1000)
            self.assertEqual(set(procs.keys()), {42})
            p = procs[42]
            self.assertEqual(p.comm, "Web Content (1) test")
            self.assertEqual(p.state, "R")
            self.assertEqual(p.ppid, 1)
            self.assertEqual(p.cmdline, ("/usr/lib/firefox/firefox", "-contentproc"))
            self.assertEqual(p.rss_kb, 204800)
            self.assertEqual(p.swap_kb, 10240)
            self.assertEqual(p.cpu_ticks, 150)
            self.assertEqual(p.start_ticks, 98765)

    def test_vanished_pid_without_status_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root, _ = build_tree(
                tmp,
                [
                    {"pid": 10, "comm": "alive", "uid": 1000, "rss_kb": 1024},
                    {"pid": 11, "comm": "vanished", "uid": 1000, "omit_status": True},
                ],
            )
            procs = scan_processes(proc_root=proc_root, uid=1000)
            self.assertEqual(set(procs.keys()), {10})

    def test_uid_filter_and_kernel_thread_without_vmrss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root, _ = build_tree(
                tmp,
                [
                    {"pid": 100, "comm": "mine", "uid": 1000, "rss_kb": None, "swap_kb": None},
                    {"pid": 200, "comm": "other", "uid": 1001, "rss_kb": 4096, "swap_kb": 0},
                ],
            )
            procs = scan_processes(proc_root=proc_root, uid=1000)
            self.assertEqual(set(procs.keys()), {100})
            self.assertEqual(procs[100].rss_kb, 0)
            self.assertEqual(procs[100].swap_kb, 0)
            self.assertEqual(procs[100].cmdline, ())

    def test_read_cgroup_memory(self) -> None:
        cg_path = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo-1.scope"
        zswap_cg_path = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-bar-1.scope"
        with tempfile.TemporaryDirectory() as tmp:
            _, cgroup_root = build_tree(
                tmp,
                [],
                cgroups={
                    cg_path: (1048576, 524288),
                    zswap_cg_path: (2097152, 1048576, 262144),
                },
            )
            self.assertEqual(read_cgroup_memory(cgroup_root, cg_path), (1048576, 524288, 0))
            self.assertEqual(
                read_cgroup_memory(cgroup_root, zswap_cg_path),
                (2097152, 1048576, 262144),
            )
            self.assertIsNone(read_cgroup_memory(cgroup_root, "/missing.scope"))
            cg_dir = cgroup_root / cg_path.lstrip("/")
            (cg_dir / "memory.current").write_text("9999999999\n", encoding="utf-8")
            (cg_dir / "memory.stat").write_text("file 9999999999\nanon 1048576\n", encoding="utf-8")
            self.assertEqual(read_cgroup_memory(cgroup_root, cg_path), (1048576, 524288, 0))
            for contents in ("file 99\n", "anon bad\n", "anon\n"):
                with self.subTest(contents=contents):
                    (cg_dir / "memory.stat").write_text(contents, encoding="utf-8")
                    self.assertIsNone(read_cgroup_memory(cgroup_root, cg_path))

    def test_uptime_and_clock_ticks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root, _ = build_tree(tmp, [], uptime=123456.75)
            self.assertEqual(read_uptime(proc_root), 123456.75)
        with patch("ramcleaner.procscan.os.sysconf", return_value=250) as sysconf:
            self.assertEqual(clock_ticks(), 250)
        sysconf.assert_called_once_with("SC_CLK_TCK")


if __name__ == "__main__":
    unittest.main()
