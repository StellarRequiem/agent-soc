"""Default SOC sources include dual actors."""

from __future__ import annotations

from collect import load_sources


def test_default_sources_include_claude_and_grok_planes():
    src = load_sources()
    assert "agent-control" in src
    assert "claude-control" in src
    assert "browser-leash" in src
    assert "desktop-leash" in src
