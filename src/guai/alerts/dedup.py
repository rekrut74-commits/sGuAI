"""Alert deduplication — suppresses duplicate alerts within a time window."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


class AlertDeduplicator:
    """Suppresses duplicate alerts within a configurable time window.

    Uses a fingerprint based on rule name and key event data to identify
    duplicates. Alerts with the same fingerprint within the suppress window
    are suppressed.
    """

    def __init__(self, suppress_window_minutes: int = 15) -> None:
        self._suppress_window_minutes = suppress_window_minutes
        self._seen: dict[str, datetime] = {}  # fingerprint -> last_seen

    def fingerprint(self, rule_name: str, key_data: dict[str, object]) -> str:
        """Generate a dedup fingerprint from rule name and key event data.

        Args:
            rule_name: Name of the rule that triggered.
            key_data: Key data from the event for dedup purposes.

        Returns:
            A hex digest string used as the fingerprint.
        """
        raw = json.dumps({"rule": rule_name, "data": key_data}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def should_suppress(self, fingerprint: str) -> bool:
        """Check if an alert with this fingerprint was seen recently.

        Args:
            fingerprint: The alert fingerprint to check.

        Returns:
            True if this alert should be suppressed (seen within window).
        """
        if fingerprint not in self._seen:
            return False

        last_seen = self._seen[fingerprint]
        now = datetime.now(tz=timezone.utc)
        elapsed_minutes = (now - last_seen).total_seconds() / 60.0
        return elapsed_minutes < self._suppress_window_minutes

    def record(self, fingerprint: str) -> None:
        """Record that an alert with this fingerprint was generated.

        Args:
            fingerprint: The alert fingerprint to record.
        """
        self._seen[fingerprint] = datetime.now(tz=timezone.utc)

    def cleanup(self) -> int:
        """Remove expired entries from the dedup cache.

        Returns:
            Number of entries removed.
        """
        now = datetime.now(tz=timezone.utc)
        expired = [
            fp
            for fp, last_seen in self._seen.items()
            if (now - last_seen).total_seconds() / 60.0 >= self._suppress_window_minutes
        ]
        for fp in expired:
            del self._seen[fp]
        return len(expired)
