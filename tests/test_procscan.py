# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import tempfile
import unittest

from ramcleaner.procscan import read_cgroup_memory, scan_processes
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
        with tempfile.TemporaryDirectory() as tmp:
            _, cgroup_root = build_tree(
                tmp,
                [],
                cgroups={cg_path: (1048576, 524288)},
            )
            self.assertEqual(read_cgroup_memory(cgroup_root, cg_path), (1048576, 524288))
            self.assertIsNone(read_cgroup_memory(cgroup_root, "/missing.scope"))


if __name__ == "__main__":
    unittest.main()
