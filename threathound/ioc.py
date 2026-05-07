"""IOC extraction from files and logs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "url": re.compile(r"https?://[^\s\"<>]+"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "bitcoin": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}


def extract_from_text(text: str) -> dict[str, list[str]]:
    """Extract IOCs from a text string.

    Args:
        text: Input text to scan.

    Returns:
        Dict mapping IOC type to sorted unique matches.
    """
    results: dict[str, list[str]] = {}
    for name, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            unique = sorted(set(matches))
            if name == "ipv4":
                unique = [m for m in unique if not m.startswith("0.") and not m.startswith("127.")]
            if name == "domain":
                unique = [m for m in unique if "." in m and (not m.endswith((".com", ".org", ".net")) or len(m) > 10)]
            if unique:
                results[name] = unique
    return results


def extract_from_file(path: Path) -> dict[str, Any]:
    """Extract IOCs and hashes from a single file.

    Args:
        path: Path to the file.

    Returns:
        Dict with file, size, hashes, and iocs.
    """
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")

    iocs = extract_from_text(text)
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    return {
        "file": str(path),
        "size": len(data),
        "hashes": hashes,
        "iocs": iocs,
    }


def extract_from_path(path: Path, recursive: bool = False) -> list[dict[str, Any]]:
    """Extract IOCs from a file or directory.

    Args:
        path: File or directory to scan.
        recursive: Whether to scan subdirectories.

    Returns:
        List of result dicts, one per file.
    """
    results: list[dict[str, Any]] = []
    if path.is_file():
        results.append(extract_from_file(path))
    elif path.is_dir():
        pattern = "**/*" if recursive else "*"
        for f in path.glob(pattern):
            if f.is_file():
                try:
                    results.append(extract_from_file(f))
                except OSError:
                    pass
    return results
