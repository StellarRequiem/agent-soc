"""AgenticDefender — observe → analyze → decide → act (local, reversible).

P0 from Grok conversation mine. Claim ceiling: agent-plane only; not enterprise SOC;
FREEZE/disarm only (no network block / MDM). Optional auto_disarm via env.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from collect import collect
from detect import detect
from respond import clear_freeze, respond

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Posture:
    last_severity: str = "info"
    consecutive_high: int = 0
    last_defend_ts: float = 0.0
    incidents: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_severity": self.last_severity,
            "consecutive_high": self.consecutive_high,
            "last_defend_ts": self.last_defend_ts,
            "incidents": list(self.incidents)[-20:],
        }


class AgenticDefender:
    """Local reversible defender over agent-soc collect/detect/respond."""

    def __init__(
        self,
        *,
        auto_defend: bool = True,
        auto_disarm: bool | None = None,
        high_streak_for_disarm: int = 2,
        cooldown_sec: float = 30.0,
        dry_run: bool = False,
    ) -> None:
        self.auto_defend = auto_defend
        self.auto_disarm = (
            auto_disarm
            if auto_disarm is not None
            else os.environ.get("AGENT_SOC_AUTO_DISARM", "").strip() in {"1", "true", "yes"}
        )
        self.high_streak_for_disarm = high_streak_for_disarm
        self.cooldown_sec = cooldown_sec
        self.dry_run = dry_run
        self.posture = Posture()

    def observe(self) -> dict[str, Any]:
        return collect()

    def analyze(self, events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if events is None:
            events = (self.observe().get("events") or [])
        return detect(events)

    def decide(self, analysis: dict[str, Any]) -> dict[str, Any]:
        sev = str(analysis.get("severity") or "info")
        rank = SEV_RANK.get(sev, 0)
        if rank >= SEV_RANK["high"]:
            self.posture.consecutive_high += 1
        else:
            self.posture.consecutive_high = 0
        self.posture.last_severity = sev

        want_freeze = rank >= SEV_RANK["high"] and self.auto_defend
        want_disarm = (
            want_freeze
            and self.auto_disarm
            and self.posture.consecutive_high >= self.high_streak_for_disarm
        )
        cooled = (time.time() - self.posture.last_defend_ts) >= self.cooldown_sec
        return {
            "severity": sev,
            "want_freeze": want_freeze and cooled,
            "want_disarm": want_disarm and cooled,
            "cooled": cooled,
            "consecutive_high": self.posture.consecutive_high,
            "dry_run": self.dry_run,
        }

    def act(self, decision: dict[str, Any], *, reason: str, alerts: list | None = None) -> dict[str, Any]:
        if self.dry_run or not (decision.get("want_freeze") or decision.get("want_disarm")):
            return {
                "ok": True,
                "acted": False,
                "dry_run": self.dry_run,
                "decision": decision,
                "detail": "no act" if not decision.get("want_freeze") else "dry_run skip write",
            }
        out = respond(
            reason=reason,
            freeze=bool(decision.get("want_freeze")),
            disarm=bool(decision.get("want_disarm")),
            alerts=alerts,
        )
        self.posture.last_defend_ts = time.time()
        path = (out.get("incident") or {}).get("id") or (out.get("path") or "")
        if path:
            self.posture.incidents.append(str(path))
        return {"ok": True, "acted": True, "respond": out, "decision": decision}

    def cycle(self, *, reason: str = "agentic_defender cycle") -> dict[str, Any]:
        obs = self.observe()
        analysis = self.analyze(obs.get("events") or [])
        decision = self.decide(analysis)
        action = self.act(decision, reason=reason, alerts=analysis.get("alerts"))
        return {
            "ok": True,
            "service": "agentic-defender",
            "events": obs.get("count"),
            "severity": analysis.get("severity"),
            "alerts": analysis.get("alerts"),
            "decision": decision,
            "action": action,
            "posture": self.posture.to_dict(),
            "claim": (
                "Local agent-plane defender. Reversible FREEZE/disarm only. "
                "Not enterprise SOC; not a stop-all-attacks guarantee."
            ),
        }

    def clear(self) -> dict[str, Any]:
        cleared = clear_freeze()
        self.posture.consecutive_high = 0
        self.posture.last_severity = "info"
        return {"ok": True, "cleared": cleared, "posture": self.posture.to_dict()}


def run_cycle(*, dry_run: bool = False, reason: str = "agentic_defender") -> dict[str, Any]:
    return AgenticDefender(dry_run=dry_run).cycle(reason=reason)
