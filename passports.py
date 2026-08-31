"""Internal-agent passport roster for catalog-spray rules.

The roster lives in passports.json next to this module. Operators edit that
file on disk. Receipt `actor` is host-stamped (see collect.py); this is not a
request header a client can set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PASSPORTS_PATH = ROOT / "passports.json"
DEFAULT_PASSPORT_ACTORS = ("grok", "claude", "codex")


def _normalize_actor(value: Any) -> str:
    return str(value or "").strip().lower()


def _actors_from_payload(data: Any) -> frozenset[str] | None:
    """Parse a roster payload. None means 'use compiled defaults'."""
    raw: Any
    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict):
        if "actors" not in data:
            return None
        raw = data.get("actors")
        if not isinstance(raw, list):
            return None
    else:
        return None
    return frozenset(_normalize_actor(a) for a in raw if _normalize_actor(a))


def load_passport_actors(path: Path | None = None) -> frozenset[str]:
    """Load the operator roster. Missing/unreadable file → compiled defaults.

    An explicit empty list (`"actors": []`) is respected: no passports.
    """
    p = path if path is not None else PASSPORTS_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return frozenset(DEFAULT_PASSPORT_ACTORS)
    parsed = _actors_from_payload(data)
    if parsed is None:
        return frozenset(DEFAULT_PASSPORT_ACTORS)
    return parsed


def actor_has_passport(
    event: dict[str, Any],
    roster: frozenset[str] | None = None,
) -> bool:
    """True when the event's host-stamped actor is on the roster.

    Missing/empty actor is never a passport. Nested headers / args are ignored.
    """
    if roster is None:
        roster = load_passport_actors()
    actor = _normalize_actor(event.get("actor"))
    if not actor:
        return False
    return actor in roster
