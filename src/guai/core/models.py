"""Core domain models for GuAI security events and alerts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from guai.core.types import AlertStatus, Severity, TrustLevel


@dataclass
class SecurityEvent:
    """Represents a single security event detected by a monitor.

    Every event starts as UNTRUSTED — trust must be explicitly elevated
    after validation by the correlation engine or a human operator.
    """

    event_id: str
    timestamp: datetime
    source: str  # e.g. "network_monitor", "process_monitor"
    severity: Severity
    category: str  # e.g. "network", "process", "auth"
    data: dict[str, Any]
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    mitre_technique: str | None = None

    @classmethod
    def create(
        cls,
        source: str,
        severity: Severity,
        category: str,
        data: dict[str, Any],
        **kwargs: Any,
    ) -> SecurityEvent:
        """Factory with auto-generated event_id and timestamp.

        Args:
            source: Origin monitor or subsystem name.
            severity: Severity level of the event.
            category: Event category (network, process, auth, ...).
            data: Arbitrary event-specific payload.
            **kwargs: Optional overrides (trust_level, mitre_technique, etc.).

        Returns:
            A new SecurityEvent instance.
        """
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc),
            source=source,
            severity=severity,
            category=category,
            data=data,
            **kwargs,
        )


@dataclass
class Alert:
    """An alert raised from one or more correlated SecurityEvents.

    Alerts have a lifecycle: NEW -> ACKNOWLEDGED -> RESOLVED / SUPPRESSED.
    """

    alert_id: str
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    source_events: list[str] = field(default_factory=list)  # event_ids
    status: AlertStatus = AlertStatus.NEW
    mitre_technique: str | None = None
    rule_name: str | None = None
    acknowledged_by: str | None = None
    resolved_at: datetime | None = None

    @classmethod
    def create(
        cls,
        severity: Severity,
        title: str,
        description: str,
        source_events: list[str] | None = None,
        **kwargs: Any,
    ) -> Alert:
        """Factory with auto-generated alert_id and timestamp.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            description: Human-readable description.
            source_events: List of SecurityEvent IDs that triggered this alert.
            **kwargs: Optional overrides (mitre_technique, rule_name, etc.).

        Returns:
            A new Alert instance.
        """
        return cls(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc),
            severity=severity,
            title=title,
            description=description,
            source_events=source_events or [],
            **kwargs,
        )
