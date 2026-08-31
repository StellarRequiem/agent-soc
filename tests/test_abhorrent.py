"""Phase C abhorrent detectors + lockdown recommendation."""

from __future__ import annotations

from detect import detect
from abhorrent import abhorrent_alerts, lockdown_recommendation


def _unknown_tools(n: int, *, actor: str | None = None) -> list[dict]:
    ev = [{"code": "UNKNOWN_TOOL", "detail": f"tool t{i}"} for i in range(n)]
    if actor is not None:
        for e in ev:
            e["actor"] = actor
    return ev


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
    # Historical name: Phase C threshold was ≥8; code (and this fixture) is ≥5
    # unlabeled / non-passport UNKNOWN_TOOL in last 200.
    ev = _unknown_tools(5)
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_tool_spray_passport_grok_exempt():
    rules = {a["rule"] for a in abhorrent_alerts(_unknown_tools(8, actor="grok"))}
    assert "ABHORRENT_TOOL_SPRAY" not in rules


def test_tool_spray_passport_claude_exempt():
    rules = {a["rule"] for a in abhorrent_alerts(_unknown_tools(8, actor="claude"))}
    assert "ABHORRENT_TOOL_SPRAY" not in rules


def test_tool_spray_actor_agent_still_fires():
    rules = {a["rule"] for a in abhorrent_alerts(_unknown_tools(5, actor="agent"))}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_tool_spray_empty_actor_still_fires():
    rules = {a["rule"] for a in abhorrent_alerts(_unknown_tools(5, actor=""))}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_tool_spray_mixed_passport_and_unlabeled():
    # 4 grok listings do not fill the spray bucket; 5 unlabeled still do.
    ev = _unknown_tools(4, actor="grok") + _unknown_tools(5)
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_tool_spray_header_actor_does_not_grant_passport():
    # Passport is host-stamped event["actor"], not a request header.
    ev = [
        {
            "code": "UNKNOWN_TOOL",
            "detail": f"tool t{i}",
            "headers": {"actor": "grok"},
        }
        for i in range(5)
    ]
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_secret_shape_still_fires_with_grok():
    ev = [
        {
            "kind": "deny",
            "code": "ARG_POLICY",
            "detail": "argument api_key=sk-live-not-real",
            "tool": "browser.type",
            "actor": "grok",
        }
    ]
    alerts = abhorrent_alerts(ev)
    assert any(a["rule"] == "ABHORRENT_SECRET_SHAPE" for a in alerts)


def test_shell_bypass_still_fires_with_grok():
    ev = [
        {"code": "UNKNOWN_TOOL", "detail": "shell_exec not in pack", "actor": "grok"},
        {"code": "CUA_BLOCKED", "detail": "ambient shell_exec not in CUA", "actor": "grok"},
    ]
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_SHELL_BYPASS" in rules
    assert "ABHORRENT_TOOL_SPRAY" not in rules


def test_path_smell_still_fires_with_grok():
    ev = [{"detail": "read ../../../etc/passwd", "actor": "grok"}]
    assert any(a["rule"] == "ABHORRENT_PATH_SMELL" for a in abhorrent_alerts(ev))


def test_template_smell_still_fires_with_grok():
    ev = [{"detail": "eval(user_input)", "actor": "grok"}]
    assert any(a["rule"] == "ABHORRENT_TEMPLATE_SMELL" for a in abhorrent_alerts(ev))


def test_highblast_spray_still_fires_with_grok():
    ev = [
        {
            "code": "HUMAN_CONFIRM_REQUIRED",
            "detail": "browser.x_post operator_confirm missing",
            "actor": "grok",
        }
        for _ in range(4)
    ]
    rules = {a["rule"] for a in abhorrent_alerts(ev)}
    assert "ABHORRENT_HIGHBLAST_SPRAY" in rules


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
