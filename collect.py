"""Collect and normalize control-plane receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

HOME = Path.home()
# Default planes; override with AGENT_SOC_RECEIPT_SOURCES="name:/path,name2:/path2"
# or YAML-style JSON file path in AGENT_SOC_SOURCES_FILE
_DEFAULT_SOURCES = {
    "browser-leash": HOME / "browser-leash" / "receipts",
    "desktop-leash": HOME / "desktop-leash" / "receipts",
    "agent-control": HOME / "agent-control" / "receipts",
    # Claude actor (PreToolUse observe/enforce receipts)
    "claude-control": HOME / "claude-control" / "receipts",
}


def load_sources() -> dict[str, Path]:
    """Configurable receipt roots (P0 conversation mine)."""
    path = os.environ.get("AGENT_SOC_SOURCES_FILE", "").strip()
    if path:
        p = Path(path).expanduser()
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("sources"):
                    return {str(k): Path(str(v)).expanduser() for k, v in data["sources"].items()}
                if isinstance(data, dict):
                    return {str(k): Path(str(v)).expanduser() for k, v in data.items() if not str(k).startswith("_")}
            except (OSError, json.JSONDecodeError, TypeError):
                pass
    env = os.environ.get("AGENT_SOC_RECEIPT_SOURCES", "").strip()
    if env:
        out: dict[str, Path] = {}
        for part in env.split(","):
            part = part.strip()
            if ":" not in part:
                continue
            name, root = part.split(":", 1)
            out[name.strip()] = Path(root.strip()).expanduser()
        if out:
            return out
    return dict(_DEFAULT_SOURCES)


SOURCES = load_sources()


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


def collect(*, max_per_file: int = 2000, sources: dict[str, Path] | None = None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    files: list[str] = []
    src = sources or load_sources()
    for plane, root in src.items():
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.jsonl")):
            files.append(str(path))
            for row in _iter_jsonl(path, max_lines=max_per_file):
                # claude-control: tool/decision; plane-host: kind/action/code
                events.append(
                    {
                        "plane": plane,
                        "source_file": path.name,
                        "ts": row.get("ts") or row.get("time") or "",
                        "actor": row.get("actor") or "",
                        "kind": (
                            row.get("kind")
                            or row.get("tool")
                            or row.get("action")
                            or row.get("code")
                            or "event"
                        ),
                        "code": row.get("code") or row.get("decision") or row.get("reason") or "",
                        "action": row.get("action") or row.get("tool") or "",
                        "mode": row.get("mode") or "",
                        "detail": str(
                            row.get("detail") or row.get("summary") or row.get("event") or ""
                        )[:200],
                        "raw_keys": sorted(row.keys())[:12],
                    }
                )
    # newest last
    events.sort(key=lambda e: str(e.get("ts") or ""))
    return {
        "ok": True,
        "schema_version": 2,
        "files": files,
        "sources": {k: str(v) for k, v in src.items()},
        "count": len(events),
        "events": events,
        "tail": events[-30:],
    }
