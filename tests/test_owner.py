# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import tempfile
import unittest

from ramcleaner.owner import Owner, group_by_owner, owner_of, resolve_owner
from ramcleaner.procscan import scan_processes
from tests.fakeproc import build_tree


class OwnerTest(unittest.TestCase):
    def test_owner_of_patterns(self) -> None:
        yakuake = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.yakuake-850410.scope/tab(850422).scope"
        )
        self.assertEqual(
            owner_of(yakuake),
            Owner(app="org.kde.yakuake", unit=None, tab="850422"),
        )
        self.assertEqual(resolve_owner(yakuake + "/child.scope"), (owner_of(yakuake), yakuake))

        konsole = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.konsole@1a2b.service/tab(9100).scope"
        )
        self.assertEqual(
            owner_of(konsole),
            Owner(app="org.kde.konsole", unit=None, tab="9100"),
        )

        escaped = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            r"app-antigravity\x2dide@09ea.service"
        )
        self.assertEqual(
            owner_of(escaped),
            Owner(app="antigravity-ide", unit=None, tab=None),
        )

        service = (
            "/user.slice/user-1000.slice/user@1000.service/session.slice/"
            "plasma-kwin_wayland.service"
        )
        self.assertEqual(
            owner_of(service),
            Owner(app=None, unit="plasma-kwin_wayland", tab=None),
        )

        fallback = "/user.slice/user-1000.slice/session-2.scope"
        self.assertEqual(
            owner_of(fallback),
            Owner(app=None, unit="session-2.scope", tab=None),
        )

    def test_held_by_picks_heavy_subtree_root_and_sorts_by_cgroup_memory(self) -> None:
        yakuake_cg = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.yakuake-850410.scope"
        )
        yakuake_tab_cg = f"{yakuake_cg}/tab(850422).scope"
        editor_cg = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.kate-1234.scope"
        )

        with tempfile.TemporaryDirectory() as tmp:
            proc_root, cgroup_root = build_tree(
                tmp,
                [
                    # Light root inside yakuake scope (ppid 1 is outside the group).
                    {
                        "pid": 100,
                        "ppid": 1,
                        "comm": "zsh",
                        "uid": 1000,
                        "rss_kb": 15000,
                        "swap_kb": 0,
                        "cgroup": yakuake_tab_cg,
                    },
                    # Heavy subtree root: small itself, but has heavy children.
                    {
                        "pid": 200,
                        "ppid": 1,
                        "comm": "codex",
                        "uid": 1000,
                        "rss_kb": 10000,
                        "swap_kb": 0,
                        "cgroup": yakuake_tab_cg,
                    },
                    {
                        "pid": 201,
                        "ppid": 200,
                        "comm": "bun",
                        "uid": 1000,
                        "rss_kb": 300000,
                        "swap_kb": 200000,
                        "cgroup": yakuake_tab_cg,
                    },
                    {
                        "pid": 202,
                        "ppid": 200,
                        "comm": "bun",
                        "uid": 1000,
                        "rss_kb": 300000,
                        "swap_kb": 200000,
                        "cgroup": yakuake_tab_cg,
                    },
                    # Second group with larger per-process RSS than kate's cgroup,
                    # used to verify cgroup values win over per-process sums when sorting.
                    {
                        "pid": 300,
                        "ppid": 1,
                        "comm": "kate",
                        "uid": 1000,
                        "rss_kb": 50000,
                        "swap_kb": 0,
                        "cgroup": editor_cg,
                    },
                ],
                cgroups={
                    # Give kate a higher cgroup memory total than yakuake's process sum.
                    editor_cg: (2 * 1024 * 1024 * 1024, 512 * 1024 * 1024),
                },
            )
            procs = scan_processes(proc_root=proc_root, uid=1000)
            usages = group_by_owner(procs, cgroup_root=cgroup_root)

            self.assertEqual(len(usages), 2)
            # kate comes first because its cgroup memory (2.5 GiB) > yakuake process sum (~1 GiB).
            self.assertEqual(usages[0].owner.app, "org.kde.kate")
            self.assertEqual(usages[0].cgroup_bytes, 2 * 1024 * 1024 * 1024)
            self.assertEqual(usages[0].cgroup_swap_bytes, 512 * 1024 * 1024)

            yakuake_usage = usages[1]
            self.assertEqual(yakuake_usage.owner, Owner(app="org.kde.yakuake", unit=None, tab="850422"))
            self.assertEqual(yakuake_usage.cgroup, yakuake_tab_cg)
            self.assertEqual(yakuake_usage.held_by.pid, 200)
            self.assertEqual(yakuake_usage.held_by.comm, "codex")

    def test_each_terminal_tab_is_its_own_owner(self) -> None:
        konsole_cg = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.konsole-2469.scope"
        )
        with tempfile.TemporaryDirectory() as tmp:
            proc_root, cgroup_root = build_tree(
                tmp,
                [
                    {"pid": 10, "ppid": 1, "comm": "konsole", "uid": 1000,
                     "rss_kb": 90000, "swap_kb": 0, "cgroup": f"{konsole_cg}/main.scope"},
                    # The tab's shell is the subtree root; the agent under it holds the memory.
                    {"pid": 20, "ppid": 10, "comm": "bash", "uid": 1000,
                     "rss_kb": 5000, "swap_kb": 0, "cgroup": f"{konsole_cg}/tab(20).scope"},
                    {"pid": 21, "ppid": 20, "comm": "claude", "uid": 1000,
                     "rss_kb": 700000, "swap_kb": 100000, "cgroup": f"{konsole_cg}/tab(20).scope"},
                    {"pid": 30, "ppid": 10, "comm": "bash", "uid": 1000,
                     "rss_kb": 5000, "swap_kb": 0, "cgroup": f"{konsole_cg}/tab(30).scope"},
                ],
                cgroups={
                    # The terminal's scope includes both tabs; only tab 20 is readable.
                    konsole_cg: (1000 * 1024**2, 200 * 1024**2),
                    f"{konsole_cg}/tab(20).scope": (800 * 1024**2, 100 * 1024**2),
                },
            )
            usages = group_by_owner(scan_processes(proc_root=proc_root, uid=1000),
                                    cgroup_root=cgroup_root)

        by_label = {u.owner.label: u for u in usages}
        self.assertEqual(set(by_label), {"org.kde.konsole", "org.kde.konsole tab 20",
                                         "org.kde.konsole tab 30"})
        self.assertEqual(usages[0].owner.label, "org.kde.konsole tab 20")
        self.assertEqual(usages[0].held_by.comm, "claude")
        terminal = by_label["org.kde.konsole"]
        self.assertEqual(terminal.ram_bytes, (1000 - 800) * 1024**2 - 5000 * 1024)
        self.assertEqual(terminal.swap_bytes, 100 * 1024**2)

    def test_three_level_hierarchy_subtracts_each_descendant_once(self) -> None:
        parent = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "app-org.kde.konsole-2469.scope"
        )
        child = f"{parent}/tab(20).scope"
        grandchild = f"{child}/tab(21).scope"
        mib = 1024**2

        with tempfile.TemporaryDirectory() as tmp:
            proc_root, cgroup_root = build_tree(
                tmp,
                [
                    {"pid": 10, "ppid": 1, "comm": "konsole", "uid": 1000,
                     "rss_kb": 1, "swap_kb": 0, "cgroup": parent},
                    {"pid": 20, "ppid": 10, "comm": "bash", "uid": 1000,
                     "rss_kb": 1, "swap_kb": 0, "cgroup": child},
                    {"pid": 21, "ppid": 20, "comm": "agent", "uid": 1000,
                     "rss_kb": 1, "swap_kb": 0, "cgroup": grandchild},
                ],
                cgroups={
                    parent: (1000 * mib, 500 * mib, 200 * mib),
                    child: (800 * mib, 400 * mib, 160 * mib),
                    grandchild: (300 * mib, 150 * mib, 60 * mib),
                },
            )
            usages = group_by_owner(
                scan_processes(proc_root=proc_root, uid=1000),
                cgroup_root=cgroup_root,
            )

        by_cg = {u.cgroup: u for u in usages}
        self.assertEqual(
            [by_cg[parent].ram_bytes, by_cg[child].ram_bytes, by_cg[grandchild].ram_bytes],
            [200 * mib, 500 * mib, 300 * mib],
        )
        self.assertEqual(
            [by_cg[parent].swap_bytes, by_cg[child].swap_bytes, by_cg[grandchild].swap_bytes],
            [100 * mib, 250 * mib, 150 * mib],
        )
        self.assertEqual(
            [
                by_cg[parent].zswap_bytes,
                by_cg[child].zswap_bytes,
                by_cg[grandchild].zswap_bytes,
            ],
            [40 * mib, 100 * mib, 60 * mib],
        )
        self.assertEqual([u.cgroup for u in usages], [child, grandchild, parent])
        self.assertEqual([u.total_bytes for u in usages], [750 * mib, 450 * mib, 300 * mib])


if __name__ == "__main__":
    unittest.main()
