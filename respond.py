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


def _http(base: str, path: str, body: dict | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=data,
        method="GET" if body is None else "POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"ok": False, "code": "HTTP_FAIL", "detail": str(e)}


def write_freeze(reason: str) -> list[str]:
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
) -> dict[str, Any]:
    actions: dict[str, Any] = {}
    if freeze:
        actions["freeze_files"] = write_freeze(reason)
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
