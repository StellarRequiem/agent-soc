"""Collect and normalize control-plane receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOME = Path.home()
SOURCES = {
    "browser-leash": HOME / "browser-leash" / "receipts",
    "desktop-leash": HOME / "desktop-leash" / "receipts",
    "agent-control": HOME / "agent-control" / "receipts",
}


def _iter_jsonl(path: Path, *, max_lines: int = 5000) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines[-max_lines:]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def collect(*, max_per_file: int = 2000) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    files: list[str] = []
    for plane, root in SOURCES.items():
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.jsonl")):
            files.append(str(path))
            for row in _iter_jsonl(path, max_lines=max_per_file):
                events.append(
                    {
                        "plane": plane,
                        "source_file": path.name,
                        "ts": row.get("ts") or row.get("time") or "",
                        "kind": row.get("kind") or row.get("action") or row.get("code") or "event",
                        "code": row.get("code") or row.get("reason") or "",
                        "action": row.get("action") or "",
                        "detail": str(row.get("detail") or row.get("summary") or "")[:200],
                        "raw_keys": sorted(row.keys())[:12],
                    }
                )
    # newest last
    events.sort(key=lambda e: str(e.get("ts") or ""))
    return {
        "ok": True,
        "files": files,
        "count": len(events),
        "events": events,
        "tail": events[-30:],
    }
