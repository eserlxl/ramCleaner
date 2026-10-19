# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ramcleaner.config import Config, ConfigError, load_config


class ConfigTest(unittest.TestCase):
    def test_missing_file_returns_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(Path(tmp) / "nonexistent.toml")
            self.assertEqual(cfg, Config())
            self.assertEqual(cfg.min_clones, 4)
            self.assertEqual(cfg.min_age_hours, 6)
            self.assertEqual(cfg.min_group_mb, 1024)
            self.assertEqual(cfg.history_hours, 24)
            self.assertEqual(cfg.min_growth_mb, 512)
            self.assertEqual(cfg.term_timeout, 10)
            self.assertEqual(cfg.ignore_for_hours, 24)
            self.assertEqual(cfg.ask_timeout_minutes, 10)
            self.assertEqual(cfg.other_users_min_mb, 512)
            self.assertEqual(cfg.protected, ())
            self.assertEqual(cfg.stop_rules, ())

    def test_valid_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text(
                'min_clones = 6\n'
                'ask_timeout_minutes = 5\n'
                'protected = ["my-daemon"]\n'
                'stop_rules = [["codex app-server", "codex app-server daemon stop"]]\n',
                encoding="utf-8",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.min_clones, 6)
            self.assertEqual(cfg.ask_timeout_minutes, 5)
            self.assertEqual(cfg.protected, ("my-daemon",))
            self.assertEqual(
                cfg.stop_rules,
                (("codex app-server", "codex app-server daemon stop"),),
            )

    def test_unknown_key_raises_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text("bogus_key = 1\n", encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(cfg_path)
            self.assertIn("bogus_key", str(ctx.exception))

    def test_wrong_type_raises_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text('min_clones = "four"\n', encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(cfg_path)
            self.assertIn("min_clones", str(ctx.exception))

    def test_integer_keys_below_minimum_raise_config_error(self) -> None:
        cases = (
            ("min_clones", 2),
            ("min_age_hours", 0),
            ("min_group_mb", 0),
            ("history_hours", 1),
            ("min_growth_mb", 0),
            ("term_timeout", 0),
            ("ignore_for_hours", 0),
            ("ask_timeout_minutes", 1),
            ("other_users_min_mb", 0),
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            for key, min_val in cases:
                with self.subTest(key=key, case="below_minimum"):
                    cfg_path.write_text(
                        f"{key} = {min_val - 1}\n", encoding="utf-8"
                    )
                    with self.assertRaises(ConfigError) as ctx:
                        load_config(cfg_path)
                    self.assertIn(key, str(ctx.exception))
                    self.assertIn(
                        f"Expected integer >= {min_val} for key '{key}'",
                        str(ctx.exception),
                    )

                with self.subTest(key=key, case="at_minimum"):
                    cfg_path.write_text(
                        f"{key} = {min_val}\n", encoding="utf-8"
                    )
                    cfg = load_config(cfg_path)
                    self.assertEqual(getattr(cfg, key), min_val)

            with self.subTest(key="ask_timeout_minutes", case="wrong_type"):
                cfg_path.write_text(
                    'ask_timeout_minutes = "ten"\n', encoding="utf-8"
                )
                with self.assertRaises(ConfigError) as ctx:
                    load_config(cfg_path)
                self.assertIn("ask_timeout_minutes", str(ctx.exception))

    def test_valid_stop_rules_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text(
                '[[stop_rules]]\n'
                'pattern = "app1"\n'
                'command = "stop-app1"\n'
                '[[stop_rules]]\n'
                'pattern = "app2"\n'
                'command = "stop-app2"\n',
                encoding="utf-8",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(
                cfg.stop_rules,
                (("app1", "stop-app1"), ("app2", "stop-app2")),
            )

            cfg_path.write_text(
                '[stop_rules]\n'
                '"app3" = "stop-app3"\n',
                encoding="utf-8",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.stop_rules, (("app3", "stop-app3"),))

    def test_invalid_stop_rules_pattern_raises_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text('stop_rules = [["(", "true"]]\n', encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(cfg_path)
            self.assertIn("(", str(ctx.exception))

    def test_invalid_stop_rules_command_raises_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            for cmd in ('""', '"   "', '"echo \'unbalanced"'):
                with self.subTest(cmd=cmd):
                    cfg_path.write_text(
                        f"stop_rules = [['valid-pattern', {cmd}]]\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(ConfigError):
                        load_config(cfg_path)


if __name__ == "__main__":
    unittest.main()
