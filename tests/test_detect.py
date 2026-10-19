# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from ramcleaner.config import Config
from ramcleaner.detect import command_key, detect, is_protected
from ramcleaner.procscan import scan_processes
from tests.fakeproc import build_tree


class DetectTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cgroup = "/app.slice/app-org.kde.yakuake-1.scope/tab(850422).scope"
        proc_root, self.cgroup_root = build_tree(
            temporary.name,
            [
                {"pid": pid, "ppid": 20, "comm": "bun",
                 "cmdline": ("/usr/bin/bun", "--silent", "/opt/context-mode/start.mjs"),
                 "rss_kb": 256 * 1024, "swap_kb": 64 * 1024,
                 "start_ticks": 100, "cpu_ticks": 10,
                 "cgroup": self.cgroup + f"/child-{pid}.scope"}
                for pid in range(10, 15)
            ],
        )
        self.procs = scan_processes(proc_root)
        for target, value in (
            ("ramcleaner.detect.os.getpid", 9000),
            ("ramcleaner.detect.os.getppid", 9001),
            ("ramcleaner.detect.time.time", 1000000),
        ):
            mock = patch(target, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def findings(self, *, first=None, second=None, config=None, history=None):
        return detect(
            self.procs if first is None else first,
            self.procs if second is None else second,
            config or Config(), 100000, 100, history or [], self.cgroup_root,
        )

    def growth_history(self, sizes=(100, 200, 300, 400)):
        return [
            {"time": 1000000 - 400 + index * 100,
             "procs": {"10:100": size * 1024}, "zombies": []}
            for index, size in enumerate(sizes)
        ]

    def test_command_key(self) -> None:
        proc = self.procs[10]
        self.assertEqual(command_key(proc), ("bun", "/opt/context-mode/start.mjs"))
        self.assertEqual(command_key(replace(proc, cmdline=())), ("bun", ""))
        self.assertEqual(command_key(replace(proc, cmdline=("/usr/bin/bun", "--silent"))),
                         ("bun", ""))

    def test_idle_clones(self) -> None:
        finding, = self.findings()
        self.assertEqual(finding.rule, "idle-clones")
        self.assertEqual(finding.owner_label, "org.kde.yakuake tab 850422")
        self.assertEqual(finding.pids, (10, 11, 12, 13, 14))
        self.assertEqual(finding.procs, tuple(self.procs[pid] for pid in (10, 11, 12, 13, 14)))
        self.assertEqual(finding.rss_kb, 5 * 256 * 1024)
        self.assertEqual(finding.swap_kb, 5 * 64 * 1024)
        self.assertEqual(finding.key,
                         f"idle-clones:{self.cgroup}:{command_key(self.procs[10])}")
        changed = {pid: replace(proc, rss_kb=proc.rss_kb + 1)
                   for pid, proc in self.procs.items()}
        self.assertEqual(self.findings(second=changed)[0].key, finding.key)

    def test_browser_renderers_are_not_clones(self) -> None:
        renderers = {pid: replace(proc, cmdline=("/opt/app/electron", "--type=renderer"))
                     for pid, proc in self.procs.items()}
        self.assertEqual(self.findings(first=renderers, second=renderers), [])

    def test_clone_thresholds(self) -> None:
        for config in (
            Config(min_clones=6),
            Config(min_age_hours=28),
            Config(min_group_mb=1601),
        ):
            with self.subTest(config=config):
                self.assertEqual(self.findings(config=config), [])
        self.assertEqual(len(self.findings(config=Config(min_group_mb=1600))), 1)

    def test_busy_or_new_members_are_excluded(self) -> None:
        for change in (
            {"cpu_ticks": 11}, {"start_ticks": 101}, {"state": "R"},
            {"start_ticks": 9999999},
        ):
            with self.subTest(change=change):
                second = {**self.procs, 10: replace(self.procs[10], **change)}
                finding, = self.findings(second=second)
                self.assertEqual(finding.pids, (11, 12, 13, 14))
                self.assertEqual(self.findings(second=second, config=Config(min_clones=5)), [])
        first = {pid: proc for pid, proc in self.procs.items() if pid != 10}
        self.assertNotIn(10, self.findings(first=first)[0].pids)
        first[10] = replace(self.procs[10], state="R")
        self.assertNotIn(10, self.findings(first=first)[0].pids)

    def test_clone_owners_and_commands_stay_separate(self) -> None:
        for changes in (
            {"cgroup": "/app.slice/other.service"},
            {"cmdline": ("bun", "/other/start.mjs")},
        ):
            with self.subTest(changes=changes):
                second = {**self.procs, 10: replace(self.procs[10], **changes)}
                self.assertEqual(self.findings(second=second, config=Config(min_clones=5)), [])

    def test_zombie_names_parent_and_groups_children(self) -> None:
        parent = replace(self.procs[10], pid=20, comm="daemon", rss_kb=42)
        second = {20: parent, 10: replace(self.procs[10], state="Z"),
                  11: replace(self.procs[11], state="Z")}
        history = [{"time": 999900, "procs": {}, "zombies": ["10:100", "11:100"]}]
        finding, = self.findings(second=second, history=history)
        self.assertEqual(finding.rule, "zombie")
        self.assertEqual(finding.key, "zombie:20:100")
        self.assertEqual(finding.pids, (20,))
        self.assertEqual(finding.procs, (parent,))
        self.assertEqual(finding.rss_kb, 42)
        self.assertIn("Parent 20 (daemon) does not reap", finding.reason)
        self.assertIn("10, 11", finding.reason)

    def test_zombie_needs_previous_scan_and_live_parent(self) -> None:
        parent = replace(self.procs[10], pid=20, comm="daemon")
        zombie = replace(self.procs[10], state="Z")
        entry = {"time": 999900, "procs": {}, "zombies": ["10:100"]}
        cases = (
            ({10: zombie, 20: parent}, []),
            ({10: zombie, 20: parent}, [entry, {**entry, "zombies": []}]),
            ({10: replace(zombie, start_ticks=101), 20: parent}, [entry]),
            ({10: zombie}, [entry]),
            ({10: zombie, 20: replace(parent, state="Z")}, [entry]),
        )
        for second, history in cases:
            with self.subTest(second=second, history=history):
                self.assertEqual(self.findings(second=second, history=history), [])

    def test_growth(self) -> None:
        proc = replace(self.procs[10], rss_kb=548 * 1024, swap_kb=64 * 1024)
        finding, = self.findings(second={10: proc}, history=self.growth_history())
        self.assertEqual(finding.rule, "growth")
        self.assertEqual(finding.key, "growth:10:100")
        self.assertEqual(finding.pids, (10,))
        self.assertEqual(finding.procs, (proc,))
        self.assertIn("512.0 MB", finding.reason)

    def test_growth_thresholds_and_identity(self) -> None:
        proc = replace(self.procs[10], rss_kb=548 * 1024, swap_kb=64 * 1024)
        history = self.growth_history()
        cases = (
            (history[:3], proc),
            (self.growth_history((100, 300, 200, 400)), proc),
            (self.growth_history((100, 200, 200, 400)), proc),
            (history, replace(proc, rss_kb=547 * 1024)),
            (history, replace(proc, start_ticks=101)),
            ([{**entry, "time": entry["time"] - 86400} for entry in history], proc),
            ([{**entry, "time": entry["time"] + 1000} for entry in history], proc),
        )
        for entries, current in cases:
            with self.subTest(entries=entries, current=current):
                self.assertEqual(self.findings(second={10: current}, history=entries), [])

    def test_protected_processes_never_appear(self) -> None:
        config = Config(min_clones=1, min_group_mb=1, protected=("custom",))
        self.assertFalse(is_protected(self.procs[10], config))
        history = self.growth_history()
        protected = [replace(self.procs[10], comm=name) for name in
                     ("systemd", "kwin_wayland", "plasmashell", "ksmserver", "custom")]
        protected += [replace(self.procs[10], pid=pid) for pid in (1, 9000, 9001)]
        for proc in protected:
            proc = replace(proc, rss_kb=1024 * 1024)
            samples = {proc.pid: proc}
            with self.subTest(proc=proc):
                self.assertTrue(is_protected(proc, config))
                self.assertEqual(self.findings(first=samples, second=samples,
                                               config=config, history=history), [])
                zombie = replace(self.procs[11], state="Z", ppid=proc.pid)
                previous = [{"time": 999900, "procs": {}, "zombies": ["11:100"]}]
                self.assertEqual(self.findings(second={**samples, 11: zombie},
                                               config=config, history=previous), [])

    def test_findings_sort_by_combined_memory(self) -> None:
        parent = replace(self.procs[10], pid=20, comm="daemon", rss_kb=2000000)
        zombie = replace(self.procs[10], pid=30, state="Z")
        history = [{"time": 999900, "procs": {}, "zombies": ["30:100"]}]
        findings = self.findings(second={**self.procs, 20: parent, 30: zombie}, history=history)
        self.assertEqual([finding.rule for finding in findings], ["zombie", "idle-clones"])


if __name__ == "__main__":
    unittest.main()
