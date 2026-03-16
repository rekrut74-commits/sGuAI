"""Helper functions for MCP server — time parsing and data formatting."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any


_SINCE_PATTERN = re.compile(r"^(\d+)\s*([mhd])$", re.IGNORECASE)

_UNITS: dict[str, str] = {
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def parse_since(since: str) -> datetime:
    """Parse a relative time string to an absolute UTC datetime.

    Supported formats:
        ``30m`` — 30 minutes ago
        ``1h``  — 1 hour ago
        ``24h`` — 24 hours ago
        ``7d``  — 7 days ago

    Args:
        since: Relative time string (e.g. ``"1h"``, ``"7d"``).

    Returns:
        UTC datetime representing the computed point in time.

    Raises:
        ValueError: If the string does not match the expected pattern.
    """
    match = _SINCE_PATTERN.match(since.strip())
    if not match:
        raise ValueError(
            f"Invalid 'since' format: '{since}'. "
            "Expected pattern like '30m', '1h', '24h', '7d'."
        )

    amount = int(match.group(1))
    unit_key = match.group(2).lower()
    unit_name = _UNITS[unit_key]

    delta = timedelta(**{unit_name: amount})
    return datetime.now(timezone.utc) - delta


def format_events(events: list[dict[str, Any]]) -> str:
    """Format a list of event dicts to a readable JSON string.

    Args:
        events: List of event dictionaries from ``EventStore.query()``.

    Returns:
        Indented JSON string.
    """
    if not events:
        return json.dumps({"events": [], "count": 0}, indent=2)

    return json.dumps(
        {"events": events, "count": len(events)},
        indent=2,
        default=str,
    )


def format_alerts(alerts: list[dict[str, Any]]) -> str:
    """Format a list of alert dicts to a readable JSON string.

    Args:
        alerts: List of alert dictionaries from ``AlertStore.list_alerts()``.

    Returns:
        Indented JSON string.
    """
    if not alerts:
        return json.dumps({"alerts": [], "count": 0}, indent=2)

    return json.dumps(
        {"alerts": alerts, "count": len(alerts)},
        indent=2,
        default=str,
    )
