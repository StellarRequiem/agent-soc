"""Abhorrent lockdown surface — engage / status / clear (mediated plane only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from collect import collect
from detect import detect
from respond import clear_freeze, respond, write_freeze

HOME = Path.home()
FREEZE_PATHS = [
    HOME / "agent-control" / "FREEZE",
    HOME / "mcp-assure" / "FREEZE",
]


def freeze_status() -> dict[str, Any]:
    files = []
    for p in FREEZE_PATHS:
        files.append(
            {
                "path": str(p),
                "active": p.is_file(),
                "preview": (p.read_text(encoding="utf-8")[:200] if p.is_file() else None),
            }
        )
    active = any(f["active"] for f in files)
    return {"ok": True, "freeze_active": active, "files": files}


def lockdown_status() -> dict[str, Any]:
    c = collect()
    d = detect(c.get("events") or [])
    fr = freeze_status()
    return {
        "ok": True,
        "code": "LOCKDOWN_STATUS",
        "freeze_active": fr["freeze_active"],
        "freeze": fr,
        "severity": d.get("severity"),
        "alerts": d.get("alerts"),
        "lockdown": d.get("lockdown"),
        "events": c.get("count"),
        "claim_ceiling": {
            "mediated_plane_lockdown": True,
            "enterprise_soc": False,
            "stops_all_agent_abuse": False,
            "requires_host_cannot_bypass": True,
        },
    }


def lockdown_engage(
    *,
    reason: str = "abhorrent lockdown engage",
    disarm: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Engage freeze (+ optional disarm). If not force, only when detectors recommend."""
    c = collect()
    d = detect(c.get("events") or [])
    rec = d.get("lockdown") or {}
    if not force and not rec.get("should_engage_lockdown"):
        return {
            "ok": True,
            "code": "LOCKDOWN_NOT_INDICATED",
            "detail": "no high/critical abhorrent recommendation — pass force=True to engage anyway",
            "severity": d.get("severity"),
            "lockdown": rec,
            "alerts": d.get("alerts"),
        }
    out = respond(
        reason=reason,
        freeze=True,
        disarm=disarm,
        alerts=d.get("alerts"),
    )
    return {
        "ok": True,
        "code": "LOCKDOWN_ENGAGED",
        "respond": out,
        "severity": d.get("severity"),
        "disarm": disarm,
        "claim": "FREEZE on mediated host — not enterprise containment",
    }


def lockdown_clear(*, reason: str = "operator clear lockdown") -> dict[str, Any]:
    cleared = clear_freeze()
    # Note reason in a small receipt
    note = HOME / "agent-soc" / "incidents" / "lockdown-clear.jsonl"
    note.parent.mkdir(parents=True, exist_ok=True)
    with note.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"reason": reason, "cleared": cleared}) + "\n")
    return {
        "ok": True,
        "code": "LOCKDOWN_CLEARED",
        "cleared": cleared,
        "detail": "remove FREEZE files; re-arm leashes intentionally if needed",
    }
