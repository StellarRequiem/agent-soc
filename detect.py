"""Detect abuse / risk shapes on agent control planes."""

from __future__ import annotations

from collections import Counter
from typing import Any


def detect(events: list[dict[str, Any]]) -> dict[str, Any]:
    alerts: list[dict[str, Any]] = []
    kinds = Counter(str(e.get("kind") or "") for e in events)
    codes = Counter(str(e.get("code") or "") for e in events[-500:])
    planes = Counter(str(e.get("plane") or "") for e in events[-500:])

    # High-blast / confirm churn
    deny_n = sum(1 for e in events[-200:] if "deny" in str(e.get("kind")).lower() or e.get("code") in (
        "NOT_ARMED", "APP_DENIED", "UNKNOWN_TOOL", "VELOCITY", "HUMAN_CONFIRM_REQUIRED", "D4_SESSION_CLOSED",
    ))
    if deny_n >= 15:
        alerts.append({
            "severity": "medium",
            "rule": "DENY_SPIKE",
            "detail": f"{deny_n} deny-class events in last 200",
            "recommendation": "review agent loops; keep arm sticky only while working",
        })

    hb = sum(1 for e in events[-100:] if "confirm" in str(e.get("kind")).lower() or e.get("code") == "CONFIRM_REQUIRED")
    if hb >= 5:
        alerts.append({
            "severity": "high",
            "rule": "HIGH_BLAST_CHURN",
            "detail": f"{hb} high-blast/confirm events in last 100",
            "recommendation": "require explicit operator OK; close D4 session when idle",
        })

    unk = sum(1 for e in events[-200:] if e.get("code") == "UNKNOWN_TOOL" or "UNKNOWN" in str(e.get("code")))
    if unk >= 3:
        alerts.append({
            "severity": "high",
            "rule": "UNKNOWN_TOOL_ATTEMPTS",
            "detail": f"{unk} unknown-tool signals",
            "recommendation": "freeze adaptive gate; inspect agent tool proposals",
        })

    # Quit / post language in detail
    risky = sum(
        1
        for e in events[-100:]
        if any(x in str(e.get("detail")).lower() + str(e.get("action")).lower() for x in ("quit", "x.post", "shell_exec"))
    )
    if risky >= 3:
        alerts.append({
            "severity": "medium",
            "rule": "RISKY_ACTION_SHAPE",
            "detail": f"{risky} quit/post/shell-shaped events",
            "recommendation": "human gate only; consider respond --freeze",
        })

    if not alerts:
        alerts.append({
            "severity": "info",
            "rule": "QUIET",
            "detail": "no rule thresholds crossed on recent window",
            "recommendation": "continue",
        })

    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = max(alerts, key=lambda a: sev_rank.get(a["severity"], 0))["severity"]

    return {
        "ok": True,
        "severity": max_sev,
        "alert_count": len([a for a in alerts if a["severity"] != "info"]),
        "alerts": alerts,
        "stats": {
            "events": len(events),
            "kinds_top": kinds.most_common(8),
            "codes_top": codes.most_common(8),
            "planes": dict(planes),
        },
    }
