"""Tests for core domain models: SecurityEvent and Alert."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from guai.core.models import Alert, SecurityEvent
from guai.core.types import AlertStatus, Severity, TrustLevel


class TestSecurityEventCreate:
    """Tests for SecurityEvent.create factory method."""

    def test_security_event_create(self) -> None:
        """Factory method generates valid event_id (UUID4) and timestamp."""
        event = SecurityEvent.create(
            source="network_monitor",
            severity=Severity.HIGH,
            category="network",
            data={"dst_ip": "10.0.0.1", "dst_port": 4444},
        )

        # event_id is a valid UUID4
        parsed = uuid.UUID(event.event_id, version=4)
        assert str(parsed) == event.event_id

        # timestamp is recent UTC
        assert event.timestamp.tzinfo is not None
        now = datetime.now(tz=timezone.utc)
        assert (now - event.timestamp).total_seconds() < 2.0

        # passed fields preserved
        assert event.source == "network_monitor"
        assert event.severity == Severity.HIGH
        assert event.category == "network"
        assert event.data == {"dst_ip": "10.0.0.1", "dst_port": 4444}

    def test_security_event_create_with_kwargs(self) -> None:
        """Factory method passes through optional keyword arguments."""
        event = SecurityEvent.create(
            source="process_monitor",
            severity=Severity.CRITICAL,
            category="process",
            data={"pid": 1234},
            mitre_technique="T1059.001",
            trust_level=TrustLevel.TRUSTED,
        )

        assert event.mitre_technique == "T1059.001"
        assert event.trust_level == TrustLevel.TRUSTED

    def test_security_event_default_untrusted(self) -> None:
        """SecurityEvent defaults to TrustLevel.UNTRUSTED."""
        event = SecurityEvent.create(
            source="auth_monitor",
            severity=Severity.MEDIUM,
            category="auth",
            data={"user": "admin"},
        )
        assert event.trust_level == TrustLevel.UNTRUSTED

    def test_security_event_unique_ids(self) -> None:
        """Each created event gets a unique event_id."""
        events = [
            SecurityEvent.create(
                source="test",
                severity=Severity.LOW,
                category="test",
                data={},
            )
            for _ in range(100)
        ]
        ids = {e.event_id for e in events}
        assert len(ids) == 100


class TestAlert:
    """Tests for Alert model."""

    def test_alert_default_new(self) -> None:
        """Alert defaults to AlertStatus.NEW."""
        alert = Alert.create(
            severity=Severity.HIGH,
            title="Suspicious connection",
            description="Outbound connection to known C2 server",
            source_events=["evt-1", "evt-2"],
        )
        assert alert.status == AlertStatus.NEW

    def test_alert_create_factory(self) -> None:
        """Alert.create generates valid alert_id and timestamp."""
        alert = Alert.create(
            severity=Severity.CRITICAL,
            title="Brute force detected",
            description="Multiple failed logins from 10.0.0.5",
            source_events=["e1"],
            rule_name="brute_force_rule",
            mitre_technique="T1110",
        )

        parsed = uuid.UUID(alert.alert_id, version=4)
        assert str(parsed) == alert.alert_id
        assert alert.timestamp.tzinfo is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.title == "Brute force detected"
        assert alert.source_events == ["e1"]
        assert alert.rule_name == "brute_force_rule"
        assert alert.mitre_technique == "T1110"
        assert alert.acknowledged_by is None
        assert alert.resolved_at is None

    def test_alert_default_empty_source_events(self) -> None:
        """Alert.create with no source_events defaults to empty list."""
        alert = Alert.create(
            severity=Severity.LOW,
            title="Info alert",
            description="Test",
        )
        assert alert.source_events == []
