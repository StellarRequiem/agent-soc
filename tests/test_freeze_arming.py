"""The automatic freeze is disarmed until an operator arms it.

Detection is not the thing being switched off — the response is. The rule that froze
this host was 97.5% false positive, and an automated action that fires wrongly is worse
than no automation: it trains everyone to route around the control, and the freeze it
produced was indistinguishable from a real one. So alerts and incidents continue; the
halt waits for a deliberate act.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import respond as R


@pytest.fixture
def arm(tmp_path, monkeypatch):
    """Point both the arm file and the freeze markers at scratch space."""
    arm_file = tmp_path / "FREEZE_ARMED"
    markers = (tmp_path / "a" / "FREEZE", tmp_path / "b" / "FREEZE")
    monkeypatch.setattr(R, "FREEZE_ARM", arm_file)
    monkeypatch.setattr(R, "FREEZE_PATHS", markers)
    return arm_file, markers


def test_disarmed_by_default(arm):
    assert R.freeze_armed() is False


def test_disarmed_writes_no_freeze_files(arm):
    _, markers = arm
    assert R.write_freeze("critical: something") == []
    assert not any(p.exists() for p in markers)


def test_armed_writes_them(arm):
    arm_file, markers = arm
    arm_file.write_text("armed\n", encoding="utf-8")
    written = R.write_freeze("critical: something")
    assert len(written) == 2 and all(p.exists() for p in markers)


def test_suppression_is_recorded_not_silent(arm):
    """A control that withholds an action without leaving a trace cannot be audited."""
    out = R.respond(reason="critical: test", freeze=True, disarm=False, alerts=[])
    assert out["actions"]["freeze_suppressed"]["armed"] is False
    assert "arm-freeze" in out["actions"]["freeze_suppressed"]["detail"]
    assert "freeze_files" not in out["actions"]


def test_an_incident_still_opens_while_disarmed(arm):
    """Disarming the response must not disarm the record of why it would have fired."""
    out = R.respond(reason="critical: test", freeze=True, disarm=False, alerts=[
        {"rule": "ABHORRENT_TOOL_SPRAY", "severity": "critical", "detail": "x"}])
    assert out["ok"] is True
    assert out.get("incident") or "incident" in str(out).lower()


def test_arming_takes_effect_without_a_restart(arm):
    """Checked fresh on every call, deliberately. An env var read at process start is
    what let a four-day-old watch keep enforcing a rule already fixed on disk."""
    arm_file, markers = arm
    assert R.write_freeze("r") == []
    arm_file.write_text("armed\n", encoding="utf-8")
    assert R.write_freeze("r") != []             # same process, no reload
    arm_file.unlink()
    for p in markers:
        p.unlink()
    assert R.write_freeze("r") == []


def test_the_gate_is_inside_write_freeze_not_only_at_the_caller(arm):
    """One check covering every path, so a new caller cannot forget it."""
    import inspect
    src = inspect.getsource(R.write_freeze)
    assert "freeze_armed()" in src


def test_an_unreadable_arm_file_reads_as_disarmed(arm, monkeypatch):
    """Fail safe toward not-halting-the-host: an unreadable switch must not be
    treated as armed."""
    def boom(self):
        raise OSError("nope")
    monkeypatch.setattr(Path, "exists", boom)
    assert R.freeze_armed() is False
