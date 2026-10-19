# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from ramcleaner.history import append_scan, default_history_path, load_history


class HistoryTest(unittest.TestCase):
    def test_atomic_append_and_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state" / "history.json"
            old = {"time": 1000, "procs": {"10:100": 50}, "zombies": []}
            boundary = {"time": 6400, "procs": {"10:100": 100}, "zombies": ["11:101"]}
            current = {"time": 10000, "procs": {"10:100": 200}, "zombies": ["11:101"]}
            append_scan(path, old, keep_hours=1, now=1000)
            append_scan(path, boundary, keep_hours=24, now=6400)
            real_replace = os.replace

            def check_replace(source, target):
                self.assertEqual(source.parent, path.parent)
                self.assertEqual(target, path)
                self.assertEqual(load_history(path), [old, boundary])
                self.assertEqual(json.loads(source.read_text(encoding="utf-8")),
                                 [boundary, current])
                real_replace(source, target)

            with patch("ramcleaner.history.os.replace", side_effect=check_replace) as replace:
                append_scan(path, current, keep_hours=1, now=10000)
            replace.assert_called_once()
            self.assertEqual(load_history(path), [boundary, current])
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_failed_replace_preserves_history_and_removes_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            entry = {"time": 1000, "procs": {}, "zombies": []}
            append_scan(path, entry, 24, 1000)
            with (
                patch("ramcleaner.history.os.replace", side_effect=OSError("replace failed")),
                self.assertRaises(OSError),
            ):
                append_scan(path, {**entry, "time": 2000}, 24, 2000)
            self.assertEqual(load_history(path), [entry])
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_malformed_history_is_empty_with_one_warning(self) -> None:
        malformed = (
            "{broken", "{}", "[null]", '[{"time": 1}]',
            '[{"time": 1, "procs": {"10:100": "bad"}, "zombies": []}]',
            '[{"time": NaN, "procs": {}, "zombies": []}]',
            '[{"time": 1, "procs": {}, "zombies": [null]}]',
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            for content in malformed:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        self.assertEqual(load_history(path), [])
                    self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                    self.assertIn("Warning:", stderr.getvalue())
            entry = {"time": 1000, "procs": {}, "zombies": []}
            with redirect_stderr(io.StringIO()):
                append_scan(path, entry, 24, 1000)
            self.assertEqual(load_history(path), [entry])

    def test_missing_history_is_empty_and_unreadable_history_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(load_history(path), [])
            self.assertEqual(stderr.getvalue(), "")
            with (
                patch.object(Path, "read_text", side_effect=PermissionError("denied")),
                redirect_stderr(stderr),
            ):
                self.assertEqual(load_history(path), [])
            self.assertEqual(len(stderr.getvalue().splitlines()), 1)

    def test_default_state_path(self) -> None:
        with patch.dict(os.environ, {"XDG_STATE_HOME": "/fixture/state"}):
            self.assertEqual(default_history_path(), Path("/fixture/state/ramcleaner/history.json"))
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, "home", return_value=Path("/fixture")):
            self.assertEqual(default_history_path(), Path("/fixture/.local/state/ramcleaner/history.json"))


if __name__ == "__main__":
    unittest.main()
