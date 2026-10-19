# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when the configuration file has an unknown key or wrong value type."""


_INT_MINIMUMS: dict[str, int] = {
    "min_clones": 2,
    "min_age_hours": 0,
    "min_group_mb": 0,
    "history_hours": 1,
    "min_growth_mb": 0,
    "term_timeout": 0,
    "ignore_for_hours": 0,
    "ask_timeout_minutes": 1,
    "other_users_min_mb": 0,
}
_INT_KEYS = frozenset(_INT_MINIMUMS)
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
    other_users_min_mb: int = 512
    protected: tuple[str, ...] = ()
    stop_rules: tuple[tuple[str, str], ...] = ()


def _default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "ramcleaner" / "config.toml"


def _validate_stop_rule(pattern: str, command: str) -> tuple[str, str]:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ConfigError(
            f"Invalid regex pattern {pattern!r} in 'stop_rules': {exc}"
        ) from exc
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise ConfigError(
            f"Invalid command in 'stop_rules': {command!r} ({exc})"
        ) from exc
    if not tokens:
        raise ConfigError(f"Empty command in 'stop_rules': {command!r}")
    return (pattern, command)


def _parse_stop_rules(raw: Any) -> tuple[tuple[str, str], ...]:
    if isinstance(raw, dict):
        if all(isinstance(k, str) and isinstance(v, str) for k, v in raw.items()):
            return tuple(_validate_stop_rule(k, v) for k, v in raw.items())
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
                pairs.append(_validate_stop_rule(item[0], item[1]))
            elif (
                isinstance(item, dict)
                and set(item.keys()) == {"pattern", "command"}
                and isinstance(item["pattern"], str)
                and isinstance(item["command"], str)
            ):
                pairs.append(_validate_stop_rule(item["pattern"], item["command"]))
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
            min_val = _INT_MINIMUMS[key]
            if val < min_val:
                raise ConfigError(f"Expected integer >= {min_val} for key '{key}'")
            kwargs[key] = val
        elif key == "protected":
            if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                raise ConfigError("Expected list of strings for key 'protected'")
            kwargs["protected"] = tuple(val)
        elif key == "stop_rules":
            kwargs["stop_rules"] = _parse_stop_rules(val)

    return Config(**kwargs)
