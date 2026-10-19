# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when the configuration file has an unknown key or wrong value type."""


_INT_KEYS = frozenset(
    {
        "min_clones",
        "min_age_hours",
        "min_group_mb",
        "history_hours",
        "min_growth_mb",
        "term_timeout",
        "ignore_for_hours",
        "ask_timeout_minutes",
    }
)
_ALL_KEYS = _INT_KEYS | {"protected", "stop_rules"}


@dataclass(frozen=True)
class Config:
    min_clones: int = 4
    min_age_hours: int = 6
    min_group_mb: int = 1024
    history_hours: int = 24
    min_growth_mb: int = 512
    term_timeout: int = 10
    ignore_for_hours: int = 24
    ask_timeout_minutes: int = 10
    protected: tuple[str, ...] = ()
    stop_rules: tuple[tuple[str, str], ...] = ()


def _default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "ramcleaner" / "config.toml"


def _parse_stop_rules(raw: Any) -> tuple[tuple[str, str], ...]:
    if isinstance(raw, dict):
        if all(isinstance(k, str) and isinstance(v, str) for k, v in raw.items()):
            return tuple((k, v) for k, v in raw.items())
        raise ConfigError("Invalid type for key 'stop_rules'")
    if isinstance(raw, list):
        pairs: list[tuple[str, str]] = []
        for item in raw:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], str)
            ):
                pairs.append((item[0], item[1]))
            elif (
                isinstance(item, dict)
                and set(item.keys()) == {"pattern", "command"}
                and isinstance(item["pattern"], str)
                and isinstance(item["command"], str)
            ):
                pairs.append((item["pattern"], item["command"]))
            else:
                raise ConfigError("Invalid type for key 'stop_rules'")
        return tuple(pairs)
    raise ConfigError("Invalid type for key 'stop_rules'")


def load_config(path: str | Path | None = None) -> Config:
    cfg_path = _default_config_path() if path is None else Path(path)
    try:
        raw_bytes = cfg_path.read_bytes()
    except FileNotFoundError:
        return Config()

    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Invalid TOML in {cfg_path}: {exc}") from exc

    kwargs: dict[str, Any] = {}
    for key, val in data.items():
        if key not in _ALL_KEYS:
            raise ConfigError(f"Unknown configuration key: {key}")
        if key in _INT_KEYS:
            if not isinstance(val, int) or isinstance(val, bool):
                raise ConfigError(f"Expected integer for key '{key}'")
            if key == "ask_timeout_minutes" and val < 1:
                raise ConfigError("Expected integer >= 1 for key 'ask_timeout_minutes'")
            kwargs[key] = val
        elif key == "protected":
            if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                raise ConfigError("Expected list of strings for key 'protected'")
            kwargs["protected"] = tuple(val)
        elif key == "stop_rules":
            kwargs["stop_rules"] = _parse_stop_rules(val)

    return Config(**kwargs)
