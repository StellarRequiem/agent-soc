"""Phase C abhorrent detectors + lockdown recommendation."""

from __future__ import annotations

from detect import detect
from abhorrent import abhorrent_alerts, lockdown_recommendation


def test_secret_shape_critical():
    ev = [
        {
            "kind": "deny",
            "code": "ARG_POLICY",
            "detail": "argument api_key=sk-live-not-real",
            "tool": "browser.type",
        }
    ]
    alerts = abhorrent_alerts(ev)
    assert any(a["rule"] == "ABHORRENT_SECRET_SHAPE" for a in alerts)
    assert any(a["severity"] == "critical" for a in alerts)


def test_shell_bypass_at_2():
    ev = [
        {"code": "UNKNOWN_TOOL", "detail": "shell_exec not in pack"},
        {"code": "CUA_BLOCKED", "detail": "ambient shell_exec not in CUA"},
    ]
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_SHELL_BYPASS" in rules


def test_tool_spray_at_8():
    ev = [{"code": "UNKNOWN_TOOL", "detail": f"tool t{i}"} for i in range(5)]
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_path_smell_at_1():
    ev = [{"detail": "read ../../../etc/passwd"}]
    assert any(a["rule"] == "ABHORRENT_PATH_SMELL" for a in abhorrent_alerts(ev))


def test_quiet_fixture_no_abhorrent():
    # Align with H2 quiet floor — no abhorrent and no base alerts
    ev = (
        [{"code": "APP_DENIED", "kind": "event"} for _ in range(9)]
        + [{"code": "CONFIRM_REQUIRED", "kind": "confirm"} for _ in range(3)]
        + [{"code": "UNKNOWN_TOOL"} for _ in range(2)]
        + [{"detail": "quit TextEdit"} for _ in range(1)]
    )
    abh = abhorrent_alerts(ev)
    assert abh == []
    out = detect(ev)
    assert out["severity"] == "info"


def test_lockdown_recommendation_on_critical():
    alerts = [
        {
            "severity": "critical",
            "rule": "ABHORRENT_SECRET_SHAPE",
            "class": "abhorrent",
        }
    ]
    rec = lockdown_recommendation(alerts)
    assert rec["should_engage_lockdown"] is True
    assert rec["max_abhorrent_severity"] == "critical"
