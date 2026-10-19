# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import ramcleaner

REPO_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(shutil.which("make") is None, "make is not installed")
class InstallTest(unittest.TestCase):
    def _clean_env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def test_checkout_launcher_help(self) -> None:
        launcher = REPO_ROOT / "bin" / "ramcleaner"
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755)
        res = subprocess.run(
            [str(launcher), "report", "--help"],
            cwd=REPO_ROOT,
            env=self._clean_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("usage: ramcleaner report", res.stdout)

    def test_make_install_and_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destdir = Path(tmp) / "stage"
            outside_cwd = Path(tmp) / "work"
            outside_cwd.mkdir()

            install_res = subprocess.run(
                ["make", "install", f"DESTDIR={destdir}", "PREFIX=/usr"],
                cwd=REPO_ROOT,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(install_res.returncode, 0, install_res.stderr)

            bin_file = destdir / "usr" / "bin" / "ramcleaner"
            self.assertTrue(bin_file.is_file())
            self.assertEqual(stat.S_IMODE(bin_file.stat().st_mode), 0o755)

            pkg_dir = destdir / "usr" / "lib" / "ramcleaner" / "ramcleaner"
            source_py = sorted(p.name for p in (REPO_ROOT / "ramcleaner").glob("*.py"))
            installed_py = sorted(p.name for p in pkg_dir.glob("*.py"))
            self.assertEqual(installed_py, source_py)
            for name in installed_py:
                self.assertEqual(stat.S_IMODE((pkg_dir / name).stat().st_mode), 0o644)

            unit_dir = destdir / "usr" / "lib" / "systemd" / "user"
            service_file = unit_dir / "ramcleaner-watch.service"
            timer_file = unit_dir / "ramcleaner-watch.timer"
            self.assertTrue(service_file.is_file())
            self.assertTrue(timer_file.is_file())
            self.assertEqual(stat.S_IMODE(service_file.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(timer_file.stat().st_mode), 0o644)

            service_text = service_file.read_text(encoding="utf-8")
            service_lines = [line.strip() for line in service_text.splitlines()]
            self.assertIn("Type=oneshot", service_lines)
            self.assertIn("ExecStart=/usr/bin/ramcleaner watch", service_lines)
            self.assertIn("TimeoutStartSec=infinity", service_lines)
            self.assertNotIn("[Install]", service_lines)
            self.assertNotIn("@BINDIR@", service_text)

            timer_lines = [
                line.strip()
                for line in timer_file.read_text(encoding="utf-8").splitlines()
            ]
            self.assertIn("OnBootSec=10min", timer_lines)
            self.assertIn("OnUnitActiveSec=15min", timer_lines)
            self.assertIn("WantedBy=timers.target", timer_lines)

            help_res = subprocess.run(
                [str(bin_file), "--help"],
                cwd=outside_cwd,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(help_res.returncode, 0, help_res.stderr)
            self.assertIn("usage: ramcleaner", help_res.stdout)

            uninstall_res = subprocess.run(
                ["make", "uninstall", f"DESTDIR={destdir}", "PREFIX=/usr"],
                cwd=REPO_ROOT,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(uninstall_res.returncode, 0, uninstall_res.stderr)
            remaining_files = [p for p in destdir.rglob("*") if p.is_file()]
            self.assertEqual(remaining_files, [])
            self.assertFalse((destdir / "usr" / "lib" / "ramcleaner").exists())

    def test_per_user_prefix_installs_units_where_systemd_looks(self) -> None:
        home = "/home/someone"
        for prefix, unit_dir in ((f"{home}/.local", f"{home}/.local/share/systemd/user"),
                                 (f"{home}/.local/", f"{home}/.local/share/systemd/user"),
                                 ("/usr", "/usr/lib/systemd/user")):
            with self.subTest(prefix=prefix):
                result = subprocess.run(
                    ["make", "-n", "install", f"PREFIX={prefix}"],
                    cwd=REPO_ROOT, env={**self._clean_env(), "HOME": home},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"{unit_dir}/ramcleaner-watch.timer", result.stdout)

    def test_make_install_rejects_mismatched_libdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = subprocess.run(
                [
                    "make",
                    "install",
                    f"DESTDIR={tmp}",
                    "PREFIX=/usr",
                    "LIBDIR=/usr/share/ramcleaner",
                ],
                cwd=REPO_ROOT,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("LIBDIR", res.stderr)


class PackageVersionTest(unittest.TestCase):
    def test_pkgbuild_and_srcinfo_match_package_version(self) -> None:
        for name, pattern in (("PKGBUILD", r"^pkgver=(\S+)$"), (".SRCINFO", r"^\tpkgver = (\S+)$")):
            with self.subTest(file=name):
                text = (REPO_ROOT / name).read_text(encoding="utf-8")
                found = re.findall(pattern, text, re.MULTILINE)
                self.assertEqual(found, [ramcleaner.__version__])


if __name__ == "__main__":
    unittest.main()
