"""Sigma rule generation from detection logic."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _dict_to_yaml(d: dict[str, Any], indent: int = 0) -> list[str]:
    """Convert a nested dict to indented YAML lines."""
    prefix = "  " * indent
    lines: list[str] = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.extend(_dict_to_yaml(v, indent + 1))
        elif isinstance(v, list):
            lines.append(f"{prefix}{k}:")
            for item in v:
                lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return lines


def generate_sigma(
    title: str,
    logsource: dict[str, str],
    detection: dict[str, Any],
    level: str = "medium",
    tags: list[str] | None = None,
    description: str = "",
    references: list[str] | None = None,
    author: str = "ThreatHound",
) -> str:
    """Generate a Sigma rule YAML string.

    Args:
        title: Rule title.
        logsource: Dict with product, service, category keys.
        detection: Sigma detection dict.
        level: Severity level (informational, low, medium, high, critical).
        tags: List of MITRE ATT&CK tags.
        description: Rule description.
        references: List of reference URLs.
        author: Rule author.

    Returns:
        Sigma rule as YAML string.
    """
    lines = [
        f"title: {title}",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        f"description: {description or title}",
    ]

    if references:
        lines.append("references:")
        for ref in references:
            lines.append(f"  - {ref}")

    lines.extend([
        f"author: {author}",
        f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}",
        "logsource:",
    ])
    for k, v in logsource.items():
        lines.append(f"  {k}: {v}")

    lines.append("detection:")
    lines.extend(_dict_to_yaml(detection, indent=2))
    lines.extend([
        "falsepositives:",
        "  - Unknown",
        f"level: {level}",
    ])

    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"  - {tag}")

    return "\n".join(lines) + "\n"


def save_sigma(rule: str, path: str | Path) -> None:
    """Save a Sigma rule to a file."""
    Path(path).write_text(rule, encoding="utf-8")
