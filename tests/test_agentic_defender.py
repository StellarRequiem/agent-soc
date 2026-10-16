"""AgenticDefender cycles — dry_run never writes FREEZE."""

from __future__ import annotations

from agentic_defender import AgenticDefender, SEV_RANK


def test_decide_quiet():
    d = AgenticDefender(dry_run=True)
    dec = d.decide({"severity": "info", "alerts": []})
    assert dec["want_freeze"] is False


def test_decide_high_wants_freeze():
    d = AgenticDefender(dry_run=True, auto_defend=True, cooldown_sec=0)
    dec = d.decide({"severity": "high", "alerts": [{"severity": "high"}]})
    assert dec["want_freeze"] is True
    assert d.posture.consecutive_high == 1


def test_disarm_needs_streak():
    d = AgenticDefender(dry_run=True, auto_disarm=True, high_streak_for_disarm=2, cooldown_sec=0)
    d.decide({"severity": "critical"})
    dec1 = d.decide({"severity": "critical"})
    # second consecutive high
    assert dec1["consecutive_high"] >= 2
    assert dec1["want_disarm"] is True


def test_dry_run_act_no_write(tmp_path, monkeypatch):
    d = AgenticDefender(dry_run=True, cooldown_sec=0)
    # force freeze desire
    dec = {"want_freeze": True, "want_disarm": False, "dry_run": True}
    out = d.act(dec, reason="test")
    assert out["acted"] is False
    assert out["dry_run"] is True


def test_sev_rank():
    assert SEV_RANK["critical"] > SEV_RANK["high"]
