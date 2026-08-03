"""Abhorrent MCP / agentic-abuse signals (mediated plane).

These rules target *shape* of tool abuse on control-plane receipts — not
content moderation of free speech, not enterprise SIEM, not "stops all AI evil."

Lockdown levers: FREEZE files (mcp-assure / agent-control) + optional leash DISARM.
"""

from __future__ import annotations

import re
from typing import Any

# High-confidence secret / credential shapes in tool args or details
# Do not treat /etc/passwd path alone as a credential secret (path detector owns that).
_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|(?<![/])password(?!_)|(?<![/])passwd(?![a-z])|private[_-]?key|secret[_-]?key|"
    r"bearer\s+[a-z0-9._\-]{20,}|"
    r"authorization:\s*bearer|aws_secret|-----BEGIN (RSA |EC )?PRIVATE KEY-----)"
)

# Path / template / packer smells (align with mcp-assure campaign smells)
_PATH_SMELL_RE = re.compile(
    r"(?i)(\.\./\.\./|/etc/passwd|/etc/shadow|~/.ssh/|%USERPROFILE%|\\\\windows\\\\system32)"
)
_TEMPLATE_SMELL_RE = re.compile(
    r"(?i)(\{\{.*\}\}|\$\{jndi:|<%.*%>|__import__\s*\(|eval\s*\(|os\.system\s*\()"
)


def _blob(e: dict[str, Any]) -> str:
    parts = [
        str(e.get("kind") or ""),
        str(e.get("code") or ""),
        str(e.get("detail") or ""),
        str(e.get("action") or ""),
        str(e.get("tool") or ""),
        str(e.get("name") or ""),
        str(e.get("arguments") or ""),
        str(e.get("args") or ""),
    ]
    return " ".join(parts)


def abhorrent_alerts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return abhorrent-class alerts (may be empty). Does not include QUIET."""
    alerts: list[dict[str, Any]] = []
    window = events[-300:] if len(events) > 300 else events

    # --- credential / secret shape (critical, any hit) ---
    secret_hits = [e for e in window[-100:] if _SECRET_RE.search(_blob(e))]
    if secret_hits:
        alerts.append(
            {
                "severity": "critical",
                "rule": "ABHORRENT_SECRET_SHAPE",
                "detail": f"{len(secret_hits)} event(s) with credential/secret-shaped payload",
                "recommendation": "lockdown engage (freeze); rotate any exposed secrets; inspect agent prompts",
                "class": "abhorrent",
            }
        )

    # --- ambient shell_exec / bypass probes ---
    shell_exec_n = sum(
        1
        for e in window[-150:]
        if "shell_exec" in _blob(e).lower()
        or (
            e.get("code") in ("CUA_BLOCKED", "UNKNOWN_TOOL")
            and "shell_exec" in _blob(e).lower()
        )
    )
    if shell_exec_n >= 2:
        alerts.append(
            {
                "severity": "high",
                "rule": "ABHORRENT_SHELL_BYPASS",
                "detail": f"{shell_exec_n} ambient shell_exec / shell-bypass shaped attempts",
                "recommendation": "freeze host; confirm agent routes only through AssuredPlaneHost",
                "class": "abhorrent",
            }
        )

    # --- path / template smells ---
    path_n = sum(1 for e in window[-100:] if _PATH_SMELL_RE.search(_blob(e)))
    tmpl_n = sum(1 for e in window[-100:] if _TEMPLATE_SMELL_RE.search(_blob(e)))
    if path_n >= 1:
        alerts.append(
            {
                "severity": "high",
                "rule": "ABHORRENT_PATH_SMELL",
                "detail": f"{path_n} path-traversal / sensitive-path shaped events",
                "recommendation": "freeze; audit shell/file tools and arg policy",
                "class": "abhorrent",
            }
        )
    if tmpl_n >= 1:
        alerts.append(
            {
                "severity": "high",
                "rule": "ABHORRENT_TEMPLATE_SMELL",
                "detail": f"{tmpl_n} template/injection-shaped events",
                "recommendation": "freeze; inspect tool arguments and model outputs",
                "class": "abhorrent",
            }
        )

    # --- high-blast without human confirm (post/quit spray) ---
    force_post = sum(
        1
        for e in window[-80:]
        if "x.post" in _blob(e).lower()
        or e.get("code") in ("HUMAN_CONFIRM_REQUIRED",)
        and "post" in _blob(e).lower()
    )
    # Only fire when many confirm-required on post/quit class + denied invent
    invent_confirm = sum(
        1
        for e in window[-80:]
        if e.get("code") == "HUMAN_CONFIRM_REQUIRED"
        and any(x in _blob(e).lower() for x in ("x_post", "x.post", "operator_confirm", "quit", "return"))
    )
    if invent_confirm >= 4:
        alerts.append(
            {
                "severity": "high",
                "rule": "ABHORRENT_HIGHBLAST_SPRAY",
                "detail": f"{invent_confirm} high-blast actions blocked for missing operator_confirm",
                "recommendation": "lockdown freeze; never invent operator_confirm=true",
                "class": "abhorrent",
            }
        )

    # --- mass unknown tool catalog probing (stricter than UNKNOWN_TOOL_ATTEMPTS=3) ---
    unk = sum(
        1
        for e in window[-200:]
        if e.get("code") == "UNKNOWN_TOOL" or "UNKNOWN_TOOL" in str(e.get("code") or "")
    )
    if unk >= 5:
        alerts.append(
            {
                "severity": "critical",
                "rule": "ABHORRENT_TOOL_SPRAY",
                "detail": f"{unk} unknown-tool probes (catalog spray)",
                "recommendation": "lockdown engage; review agent tool proposal loop",
                "class": "abhorrent",
            }
        )

    return alerts


def lockdown_recommendation(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    abh = [a for a in alerts if a.get("class") == "abhorrent" or str(a.get("rule", "")).startswith("ABHORRENT_")]
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = "info"
    if abh:
        max_sev = max(abh, key=lambda a: sev_rank.get(a.get("severity", "info"), 0)).get("severity", "info")
    engage = max_sev in ("high", "critical")
    return {
        "abhorrent_alert_count": len(abh),
        "max_abhorrent_severity": max_sev,
        "should_engage_lockdown": engage,
        "default_actions": {
            "freeze": True if engage else False,
            "disarm": False,  # freeze-only unless operator / AGENT_SOC_AUTO_DISARM
        },
        "claim": "mediated-plane abhorrent lockdown recommendation — not full SOC",
    }
