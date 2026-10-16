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


# ---------------------------------------------- catalog spray: scope it to a catalog

def _unknown(plane, tool, n):
    return [{"plane": plane, "code": "UNKNOWN_TOOL", "action": tool,
             "kind": tool, "ts": f"2026-09-01T00:00:{i:02d}Z", "detail": ""}
            for i in range(n)]


def test_claude_harness_tools_do_not_trigger_a_catalog_spray():
    """The rule infers that an agent is enumerating a plane's tool catalog by calling
    names that do not exist. That inference needs a catalog to probe.

    `claude-control` logs Claude's own harness tools — ToolSearch, AskUserQuestion,
    ScheduleWakeup, every mcp__Claude_Browser__* — which were never in the plane
    catalog and never should be. On the live stream these were 2,082 of 2,136
    UNKNOWN_TOOL events, so any 200-event window touching Claude working at all fired
    a critical alert and froze the plane continuously.
    """
    from abhorrent import abhorrent_alerts
    events = _unknown("claude-control", "ToolSearch", 40)
    rules = [a["rule"] for a in abhorrent_alerts(events)]
    assert "ABHORRENT_TOOL_SPRAY" not in rules


def test_real_plane_probing_still_fires():
    """The 2.5% that mattered must still be caught, at the same threshold."""
    from abhorrent import abhorrent_alerts
    events = _unknown("agent-control", "browser.press", 5)
    rules = [a["rule"] for a in abhorrent_alerts(events)]
    assert "ABHORRENT_TOOL_SPRAY" in rules


def test_exempt_traffic_does_not_pad_the_count_toward_the_threshold():
    """Four genuine probes plus a flood of harness noise must stay under threshold —
    otherwise the exemption is cosmetic and the rule still fires on Claude working."""
    from abhorrent import abhorrent_alerts
    events = _unknown("claude-control", "ToolSearch", 150) + \
        _unknown("agent-control", "browser.press", 4)
    rules = [a["rule"] for a in abhorrent_alerts(events)]
    assert "ABHORRENT_TOOL_SPRAY" not in rules


def test_the_alert_names_which_plane_was_probed():
    """A critical alert that freezes the host should say where the probing came from;
    the original detail said only how many, which is why the false positive survived
    so long unexamined."""
    from abhorrent import abhorrent_alerts
    events = _unknown("agent-control", "shell_exec", 6)
    (a,) = [x for x in abhorrent_alerts(events) if x["rule"] == "ABHORRENT_TOOL_SPRAY"]
    assert "agent-control" in a["detail"]
