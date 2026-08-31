"""Passport roster load + collect actor copy."""

from __future__ import annotations

import json

import collect as collect_mod
from passports import (
    DEFAULT_PASSPORT_ACTORS,
    actor_has_passport,
    load_passport_actors,
)


def test_default_file_roster():
    roster = load_passport_actors()
    assert roster == frozenset(DEFAULT_PASSPORT_ACTORS)
    assert "grok" in roster and "claude" in roster and "codex" in roster
    assert "agent" not in roster


def test_empty_roster_file_is_respected(tmp_path):
    p = tmp_path / "passports.json"
    p.write_text(json.dumps({"actors": []}), encoding="utf-8")
    assert load_passport_actors(p) == frozenset()
    ev = {"code": "UNKNOWN_TOOL", "actor": "grok"}
    assert actor_has_passport(ev, frozenset()) is False


def test_missing_file_falls_back_to_defaults(tmp_path):
    assert load_passport_actors(tmp_path / "nope.json") == frozenset(DEFAULT_PASSPORT_ACTORS)


def test_corrupt_file_falls_back_to_defaults(tmp_path):
    p = tmp_path / "passports.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_passport_actors(p) == frozenset(DEFAULT_PASSPORT_ACTORS)


def test_actor_match_is_case_insensitive():
    roster = frozenset({"grok"})
    assert actor_has_passport({"actor": "GROK"}, roster) is True
    assert actor_has_passport({"actor": " grok "}, roster) is True
    assert actor_has_passport({"actor": ""}, roster) is False
    assert actor_has_passport({}, roster) is False
    assert actor_has_passport({"headers": {"actor": "grok"}}, roster) is False


def test_collect_copies_actor(tmp_path, monkeypatch):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    row = {
        "ts": "2026-08-31T12:00:00Z",
        "code": "UNKNOWN_TOOL",
        "actor": "grok",
        "detail": "browser.press not in pack",
        "headers": {"actor": "ignored-header"},
    }
    (receipts / "plane-host.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(collect_mod, "SOURCES", {"agent-control": receipts})
    out = collect_mod.collect()
    assert out["count"] == 1
    ev = out["events"][0]
    assert ev["actor"] == "grok"
    assert ev["code"] == "UNKNOWN_TOOL"


def test_collect_missing_actor_is_empty(tmp_path, monkeypatch):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    row = {"ts": "2026-08-31T12:00:01Z", "code": "UNKNOWN_TOOL", "detail": "x"}
    (receipts / "plane-host.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(collect_mod, "SOURCES", {"agent-control": receipts})
    ev = collect_mod.collect()["events"][0]
    assert ev["actor"] == ""
    assert actor_has_passport(ev) is False
