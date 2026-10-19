# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import math
import os
import re
import sys
import tempfile
from pathlib import Path


def default_history_path() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "ramcleaner" / "history.json"


def _valid_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    stamp = entry.get("time")
    procs = entry.get("procs")
    zombies = entry.get("zombies")
    boot_id = entry.get("boot_id")
    return (
        type(stamp) in (int, float)
        and math.isfinite(stamp)
        and isinstance(procs, dict)
        and all(
            isinstance(key, str)
            and re.fullmatch(r"[0-9]+:[0-9]+", key) is not None
            and type(value) is int
            and value >= 0
            for key, value in procs.items()
        )
        and isinstance(zombies, list)
        and all(
            isinstance(key, str) and re.fullmatch(r"[0-9]+:[0-9]+", key) is not None
            for key in zombies
        )
        and (boot_id is None or (isinstance(boot_id, str) and boot_id != ""))
    )


def load_history(path: str | Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list) or not all(_valid_entry(entry) for entry in data):
            raise ValueError("invalid history entries")
        return data
    except FileNotFoundError:
        return []
    except (OSError, ValueError, OverflowError) as exc:
        print(f"Warning: cannot read history {path}: {exc}", file=sys.stderr)
        return []


def write_json_atomic(path: str | Path, data: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temp_path = Path(stream.name)
            json.dump(data, stream)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def append_scan(path: str | Path, entry: dict, keep_hours: float, now: float) -> None:
    path = Path(path)
    cutoff = now - keep_hours * 3600
    entries = [item for item in [*load_history(path), entry] if item["time"] >= cutoff]
    entries.sort(key=lambda item: item["time"])
    write_json_atomic(path, entries)
