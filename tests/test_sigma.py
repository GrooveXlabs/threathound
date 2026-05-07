"""Tests for threathound.sigma."""

from __future__ import annotations

import pytest

from threathound.sigma import generate_sigma


def test_generate_sigma_basic() -> None:
    rule = generate_sigma(
        title="Test Rule",
        logsource={"product": "windows"},
        detection={"selection": {"EventID": 4688}},
        level="high",
    )
    assert "title: Test Rule" in rule
    assert "logsource:" in rule
    assert "detection:" in rule
    assert "level: high" in rule
    assert "id:" in rule


def test_generate_sigma_with_tags() -> None:
    rule = generate_sigma(
        title="Tagged Rule",
        logsource={"product": "linux"},
        detection={},
        tags=["attack.execution", "attack.t1059"],
    )
    assert "attack.execution" in rule
    assert "attack.t1059" in rule
