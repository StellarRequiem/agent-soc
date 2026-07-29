"""Re-runnable proof for the agent-soc detector and auto-freeze path.

The public claim is "collect / detect / respond with optional auto-freeze."
These tests are the evidence behind that claim: each detection rule must fire
at its threshold and stay quiet just below it, severity must resolve to the
worst alert, and the freeze/incident response must write what it says it does.

Everything runs offline against temp paths — no bridge, no network, and never
the real FREEZE files, so running the suite cannot disturb a live system.
"""

from __future__ import annotations

import json
from typing import Any

import detect as detect_mod
import respond as respond_mod
import watch as watch_mod
from detect import detect


def _events(code: str = "", *, n: int, kind: str = "event", detail: str = "", action: str = "") -> list[dict[str, Any]]:
    return [
        {"plane": "agent-control", "ts": f"2026-07-28T00:00:{i:02d}Z", "kind": kind, "code": code, "detail": detail, "action": action}
        for i in range(n)
    ]


# ---- QUIET baseline -------------------------------------------------------

def test_quiet_on_empty():
    out = detect([])
    assert out["severity"] == "info"
    assert out["alert_count"] == 0
    assert [a["rule"] for a in out["alerts"]] == ["QUIET"]


def test_quiet_below_every_threshold():
    # All rules just under the line. NOTE: UNKNOWN_TOOL is deny-class too, so it
    # counts toward BOTH deny_n and unk — 12 APP_DENIED + 2 UNKNOWN_TOOL = 14
    # deny-class events, one under the DENY_SPIKE threshold of 15.
    ev = (
        _events("APP_DENIED", n=12)
        + _events("CONFIRM_REQUIRED", n=4, kind="confirm")
        + _events("UNKNOWN_TOOL", n=2)
        + _events(n=2, detail="quit TextEdit")
    )
    out = detect(ev)
    assert out["severity"] == "info"
    assert out["alert_count"] == 0


# ---- DENY_SPIKE (medium, >= 15 in last 200) -------------------------------

def test_deny_spike_fires_at_15():
    out = detect(_events("APP_DENIED", n=15))
    rules = {a["rule"] for a in out["alerts"]}
    assert "DENY_SPIKE" in rules
    assert out["severity"] == "medium"


def test_deny_spike_quiet_at_14():
    out = detect(_events("NOT_ARMED", n=14))
    assert "DENY_SPIKE" not in {a["rule"] for a in out["alerts"]}


# ---- HIGH_BLAST_CHURN (high, >= 5 confirm in last 100) --------------------

def test_high_blast_churn_fires_at_5():
    out = detect(_events("CONFIRM_REQUIRED", n=5, kind="confirm_required"))
    rules = {a["rule"] for a in out["alerts"]}
    assert "HIGH_BLAST_CHURN" in rules
    assert out["severity"] == "high"


def test_high_blast_churn_quiet_at_4():
    out = detect(_events("CONFIRM_REQUIRED", n=4, kind="confirm_required"))
    assert "HIGH_BLAST_CHURN" not in {a["rule"] for a in out["alerts"]}


# ---- UNKNOWN_TOOL_ATTEMPTS (high, >= 3 in last 200) -----------------------

def test_unknown_tool_fires_at_3():
    out = detect(_events("UNKNOWN_TOOL", n=3))
    rules = {a["rule"] for a in out["alerts"]}
    assert "UNKNOWN_TOOL_ATTEMPTS" in rules
    assert out["severity"] == "high"


# ---- RISKY_ACTION_SHAPE (medium, >= 3 quit/post/shell in last 100) --------

def test_risky_action_shape_fires_at_3():
    out = detect(_events(n=3, detail="x.post to timeline"))
    assert "RISKY_ACTION_SHAPE" in {a["rule"] for a in out["alerts"]}


# ---- severity resolves to the worst alert ---------------------------------

def test_severity_is_max_across_rules():
    ev = _events("APP_DENIED", n=15) + _events("UNKNOWN_TOOL", n=3)  # medium + high
    out = detect(ev)
    assert out["severity"] == "high"
    assert out["alert_count"] >= 2


# ---- respond: freeze + incident, against TEMP paths only ------------------

def test_respond_writes_freeze_and_incident(tmp_path, monkeypatch):
    freeze_a = tmp_path / "a" / "FREEZE"
    freeze_b = tmp_path / "b" / "FREEZE"
    monkeypatch.setattr(respond_mod, "FREEZE_PATHS", [freeze_a, freeze_b])
    monkeypatch.setattr(respond_mod, "INCIDENTS", tmp_path / "incidents")

    out = respond_mod.respond(reason="unit-proof spike", freeze=True, disarm=False, alerts=[{"rule": "UNKNOWN_TOOL_ATTEMPTS", "severity": "high"}])

    assert out["code"] == "RESPONDED"
    # both freeze files written, carrying the reason
    assert freeze_a.is_file() and freeze_b.is_file()
    assert "unit-proof spike" in freeze_a.read_text(encoding="utf-8")
    # incident json + index recorded
    inc_path = out["incident"]["path"]
    doc = json.loads(open(inc_path, encoding="utf-8").read())
    assert doc["reason"] == "unit-proof spike"
    assert (tmp_path / "incidents" / "index.jsonl").is_file()
    # disarm was OFF -> no bridge call attempted
    assert "disarm" not in out["actions"]


# ---- watch: auto-freeze fires ONLY on high/critical -----------------------

def _install_recording_watch(monkeypatch, tmp_path, events: list[dict[str, Any]]):
    calls: list[str] = []
    monkeypatch.setattr(watch_mod, "collect", lambda: {"ok": True, "count": len(events), "events": events})
    monkeypatch.setattr(watch_mod, "WATCH_LOG", tmp_path / "watch.jsonl")

    def _fake_respond(**kwargs):
        calls.append(kwargs.get("reason", ""))
        return {"ok": True, "code": "RESPONDED", "reason": kwargs.get("reason")}

    monkeypatch.setattr(watch_mod, "respond", _fake_respond)
    return calls


def test_watch_auto_freezes_on_high(tmp_path, monkeypatch):
    calls = _install_recording_watch(monkeypatch, tmp_path, _events("UNKNOWN_TOOL", n=3))  # high
    out = watch_mod.watch_once(auto_respond_high=True, reason="proof")
    assert out["severity"] == "high"
    assert len(calls) == 1  # responded exactly once


def test_watch_does_not_freeze_when_quiet(tmp_path, monkeypatch):
    calls = _install_recording_watch(monkeypatch, tmp_path, [])  # quiet
    out = watch_mod.watch_once(auto_respond_high=True, reason="proof")
    assert out["severity"] == "info"
    assert calls == []  # never responded


def test_watch_ignores_high_when_flag_off(tmp_path, monkeypatch):
    calls = _install_recording_watch(monkeypatch, tmp_path, _events("UNKNOWN_TOOL", n=3))
    watch_mod.watch_once(auto_respond_high=False, reason="proof")
    assert calls == []  # auto-respond disabled -> no freeze even on high


# keep the linter honest about the imported module handle
assert detect_mod is not None
