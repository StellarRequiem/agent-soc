"""Continuous agent-soc watch — poll collect/detect; optional auto-respond."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from collect import collect  # noqa: E402
from detect import detect  # noqa: E402
from respond import respond  # noqa: E402

WATCH_LOG = ROOT / "incidents" / "watch.jsonl"


def _log(event: dict[str, Any]) -> None:
    WATCH_LOG.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **event,
    }
    with WATCH_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
    print(json.dumps(event), flush=True)


def _abhorrent_alerts(alerts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """H3: only class=abhorrent (or ABHORRENT_* rules) auto-engage."""
    out = []
    for a in alerts or []:
        if a.get("class") == "abhorrent":
            out.append(a)
            continue
        rule = str(a.get("rule") or "")
        if rule.startswith("ABHORRENT_"):
            out.append(a)
    return out


def watch_once(
    *,
    auto_respond_high: bool = False,
    reason: str = "agent-soc watch",
) -> dict[str, Any]:
    c = collect()
    d = detect(c.get("events") or [])
    sev = d.get("severity") or "info"
    alerts = d.get("alerts") or []
    abh = _abhorrent_alerts(alerts)
    lock = d.get("lockdown") or {}
    out: dict[str, Any] = {
        "ok": True,
        "kind": "watch_tick",
        "events": c.get("count"),
        "severity": sev,
        "alert_count": d.get("alert_count"),
        "alerts": alerts,
        "abhorrent_alert_count": len(abh),
        "lockdown": lock,
    }
    # H3: auto-respond only on abhorrent class (not every high like generic HIGH_BLAST_CHURN)
    if auto_respond_high and abh and lock.get("should_engage_lockdown"):
        import os

        disarm = os.environ.get("AGENT_SOC_AUTO_DISARM", "0") in ("1", "true", "yes")
        r = respond(
            reason=f"{reason}: abhorrent severity={sev} rules={[a.get('rule') for a in abh]}",
            freeze=True,
            disarm=disarm,
            alerts=abh,
        )
        out["responded"] = r
        out["respond_filter"] = "abhorrent_only"
    elif auto_respond_high and sev in ("high", "critical") and not abh:
        out["respond_skipped"] = "high_without_abhorrent_class"
    _log(out)
    return out


def watch_loop(
    *,
    interval_sec: float = 30.0,
    auto_respond_high: bool = False,
    max_ticks: int | None = None,
    reason: str = "agent-soc watch",
) -> int:
    interval_sec = max(5.0, float(interval_sec))
    tick = 0
    _log(
        {
            "kind": "watch_start",
            "interval_sec": interval_sec,
            "auto_respond_high": auto_respond_high,
            "max_ticks": max_ticks,
        }
    )
    try:
        while True:
            tick += 1
            watch_once(auto_respond_high=auto_respond_high, reason=reason)
            if max_ticks is not None and tick >= max_ticks:
                _log({"kind": "watch_stop", "reason": "max_ticks", "ticks": tick})
                return 0
            time.sleep(interval_sec)
    except KeyboardInterrupt:
        _log({"kind": "watch_stop", "reason": "keyboard", "ticks": tick})
        return 0
