"""Respond: freeze + disarm control planes + open incident."""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any

HOME = Path.home()
INCIDENTS = Path(__file__).resolve().parent / "incidents"
FREEZE_PATHS = [
    HOME / "agent-control" / "FREEZE",
    HOME / "mcp-assure" / "FREEZE",
]


def _http(
    base: str,
    path: str,
    body: dict | None = None,
    *,
    timeout: float = 10.0,
    retries: int = 2,
) -> dict[str, Any]:
    """HTTP with timeout + retry (P1 conversation mine)."""
    data = None if body is None else json.dumps(body).encode()
    last: dict[str, Any] = {"ok": False, "code": "HTTP_FAIL"}
    for attempt in range(max(1, retries + 1)):
        req = urllib.request.Request(
            base.rstrip("/") + path,
            data=data,
            method="GET" if body is None else "POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            last = {"ok": False, "code": "HTTP_FAIL", "detail": str(e), "attempt": attempt + 1}
            if attempt < retries:
                time.sleep(0.15 * (attempt + 1))
    return last


#: Presence of this file arms the automatic freeze. Absent = detect and report only.
#:
#: Deliberately a file rather than a config key or an env var. It has to be visible to
#: a human with `ls`, settable without editing code, and — crucially — checked fresh on
#: every call, so arming or disarming takes effect without restarting the watch. An env
#: var would have been read once at process start, which is exactly the trap that let a
#: four-day-old watch keep enforcing a rule that had already been fixed on disk.
FREEZE_ARM = Path.home() / "agent-soc" / "FREEZE_ARMED"


def freeze_armed() -> bool:
    """Is the automatic freeze response armed?

    Disarmed by default, on purpose. Detection keeps running and incidents keep
    opening; what is withheld is the automatic *response*. The rule that froze this
    host was 97.5% false positive, and an automated action that fires wrongly is worse
    than no automation: it trains everyone to route around the control, and the freeze
    it produced was indistinguishable from a real one.

    Re-arm by creating the file — `agent-soc arm-freeze`, or `touch` it. That is a
    deliberate act at a moment of the operator's choosing, which is what a higher
    defensive posture should cost.
    """
    try:
        return FREEZE_ARM.exists()
    except OSError:
        return False


def write_freeze(reason: str) -> list[str]:
    # Gate here rather than only at the caller: every path to a freeze passes through
    # this function, so one check covers them all and a new caller cannot forget it.
    if not freeze_armed():
        return []
    written = []
    payload = f"agent-soc freeze\nreason={reason}\nts={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
    for p in FREEZE_PATHS:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(payload, encoding="utf-8")
            written.append(str(p))
        except OSError:
            continue
    return written


def clear_freeze() -> list[str]:
    cleared = []
    for p in FREEZE_PATHS:
        if p.is_file():
            try:
                p.unlink()
                cleared.append(str(p))
            except OSError:
                pass
    return cleared


def disarm_all() -> dict[str, Any]:
    browser = _http("http://127.0.0.1:8756", "/v1/arm", {"armed": False})
    # browser may use different arm API — try status only if fail
    desktop = _http("http://127.0.0.1:8757", "/v1/arm", {"armed": False})
    d4 = _http("http://127.0.0.1:8757", "/v1/d4-session", {"open": False})
    return {"browser_arm": browser, "desktop_arm": desktop, "d4_session": d4}


def open_incident(*, reason: str, alerts: list[dict[str, Any]] | None = None, actions: dict[str, Any] | None = None) -> dict[str, Any]:
    INCIDENTS.mkdir(parents=True, exist_ok=True)
    iid = f"inc-{time.strftime('%Y%m%d-%H%M%S')}"
    doc = {
        "id": iid,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "alerts": alerts or [],
        "actions": actions or {},
        "claim": "agent-plane incident — not enterprise SOC ticket",
    }
    path = INCIDENTS / f"{iid}.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    # append index
    idx = INCIDENTS / "index.jsonl"
    with idx.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"id": iid, "ts": doc["ts"], "reason": reason}) + "\n")
    return {"ok": True, "incident": doc, "path": str(path)}


def respond(
    *,
    reason: str,
    freeze: bool = True,
    disarm: bool = True,
    alerts: list[dict[str, Any]] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    actions: dict[str, Any] = {}
    if dry_run:
        actions["dry_run"] = True
        actions["would_freeze"] = [str(p) for p in FREEZE_PATHS] if freeze else []
        actions["would_disarm"] = bool(disarm)
        return {
            "ok": True,
            "dry_run": True,
            "reason": reason,
            "actions": actions,
            "alerts": alerts or [],
            "claim": "dry-run — no FREEZE written, no disarm",
        }
    if freeze:
        if freeze_armed():
            actions["freeze_files"] = write_freeze(reason)
        else:
            # Recorded, not silent. A suppressed response that leaves no trace is a
            # control you cannot audit, and the incident below still opens.
            actions["freeze_suppressed"] = {
                "armed": False,
                "arm_file": str(FREEZE_ARM),
                "detail": "auto-freeze disarmed; detection and incident unaffected. "
                          "Re-arm with `agent-soc arm-freeze`.",
            }
    if disarm:
        actions["disarm"] = disarm_all()
    inc = open_incident(reason=reason, alerts=alerts, actions=actions)
    return {
        "ok": True,
        "code": "RESPONDED",
        "reason": reason,
        "actions": actions,
        "incident": inc,
        "note": "Operator must re-arm leashes and clear FREEZE when safe",
    }


def list_incidents(limit: int = 20) -> dict[str, Any]:
    INCIDENTS.mkdir(parents=True, exist_ok=True)
    files = sorted(INCIDENTS.glob("inc-*.json"), reverse=True)[:limit]
    items = []
    for p in files:
        try:
            items.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            items.append({"path": str(p), "error": "read_fail"})
    return {"ok": True, "count": len(items), "incidents": items}
