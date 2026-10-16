"""Specialist defender stubs (batch-1 P2).

ShellBypass / SecretShape — thin wrappers that call abhorrent detectors.
Full multi-specialist orchestration is future work.
"""

from __future__ import annotations

from typing import Any

from abhorrent import abhorrent_alerts
from collect import collect
from detect import detect


def shell_bypass_scan(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    events = events if events is not None else (collect().get("events") or [])
    alerts = [a for a in abhorrent_alerts(events) if "SHELL" in str(a.get("rule") or "")]
    return {"ok": True, "specialist": "ShellBypass", "alerts": alerts, "count": len(alerts)}


def secret_shape_scan(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    events = events if events is not None else (collect().get("events") or [])
    alerts = [a for a in abhorrent_alerts(events) if "SECRET" in str(a.get("rule") or "")]
    return {"ok": True, "specialist": "SecretShape", "alerts": alerts, "count": len(alerts)}


def all_specialists() -> dict[str, Any]:
    c = collect()
    ev = c.get("events") or []
    return {
        "ok": True,
        "events": c.get("count"),
        "shell_bypass": shell_bypass_scan(ev),
        "secret_shape": secret_shape_scan(ev),
        "full_detect": detect(ev),
        "claim": "Specialist stubs — same ceiling as agent-soc; not enterprise coverage.",
    }
