"""Tests for threathound.ioc."""

from __future__ import annotations

from pathlib import Path

import pytest

from threathound.ioc import extract_from_text, extract_from_file


def test_extract_ipv4() -> None:
    text = "Connect to 192.168.1.1 and 10.0.0.1"
    result = extract_from_text(text)
    assert "ipv4" in result
    assert "192.168.1.1" in result["ipv4"]
    assert "10.0.0.1" in result["ipv4"]


def test_extract_url() -> None:
    text = "Visit https://example.com/path and http://test.org"
    result = extract_from_text(text)
    assert "url" in result
    assert "https://example.com/path" in result["url"]


def test_extract_hashes() -> None:
    text = "Hash: a" * 32 + " and b" * 40  # md5 and sha1 lengths
    result = extract_from_text(text)
    # The patterns should match hex strings of correct length


def test_extract_from_file(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("Contact attacker@evil.com at 203.0.113.45")
    result = extract_from_file(f)
    assert result["file"] == str(f)
    assert "hashes" in result
    assert "md5" in result["hashes"]
    assert "email" in result["iocs"] or "ipv4" in result["iocs"]
