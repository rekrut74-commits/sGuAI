"""Tests for the alert manager, deduplicator, and CLI channel."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guai.alerts.channels import AlertChannel, CLIChannel
from guai.alerts.dedup import AlertDeduplicator
from guai.alerts.manager import AlertManager
from guai.core.models import Alert, SecurityEvent
from guai.core.types import Severity
from guai.rules.models import DetectionRule, RuleMatch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_event(
    category: str = "auth",
    data: dict | None = None,
    severity: Severity = Severity.MEDIUM,
    source: str = "event_log",
) -> SecurityEvent:
    """Helper to create a SecurityEvent quickly."""
    return SecurityEvent.create(
        source=source,
        severity=severity,
        category=category,
        data=data or {},
    )


def _make_rule(
    name: str = "test_rule",
    severity: Severity = Severity.HIGH,
) -> DetectionRule:
    return DetectionRule(
        name=name,
        description=f"Test rule: {name}",
        severity=severity,
        source="event_log",
        conditions={"category": "auth"},
    )


def _make_match(
    rule: DetectionRule | None = None,
    events: list[SecurityEvent] | None = None,
) -> RuleMatch:
    if rule is None:
        rule = _make_rule()
    if events is None:
        events = [_make_event()]
    return RuleMatch(
        rule=rule,
        events=events,
        matched_at=datetime.now(tz=timezone.utc),
        count=len(events),
    )


# ---------------------------------------------------------------------------
# AlertDeduplicator tests
# ---------------------------------------------------------------------------


class TestAlertDeduplicator:
    def test_fingerprint_deterministic(self) -> None:
        """Same inputs produce the same fingerprint."""
        dedup = AlertDeduplicator()
        fp1 = dedup.fingerprint("rule_a", {"category": "auth"})
        fp2 = dedup.fingerprint("rule_a", {"category": "auth"})
        assert fp1 == fp2

    def test_fingerprint_differs_for_different_rules(self) -> None:
        """Different rule names produce different fingerprints."""
        dedup = AlertDeduplicator()
        fp1 = dedup.fingerprint("rule_a", {"category": "auth"})
        fp2 = dedup.fingerprint("rule_b", {"category": "auth"})
        assert fp1 != fp2

    def test_dedup_suppresses_duplicate(self) -> None:
        """After recording, the same fingerprint is suppressed."""
        dedup = AlertDeduplicator(suppress_window_minutes=15)
        fp = dedup.fingerprint("rule_a", {"category": "auth"})

        assert dedup.should_suppress(fp) is False
        dedup.record(fp)
        assert dedup.should_suppress(fp) is True

    def test_dedup_allows_after_window(self) -> None:
        """After the suppress window expires, the fingerprint is no longer suppressed."""
        dedup = AlertDeduplicator(suppress_window_minutes=1)
        fp = dedup.fingerprint("rule_a", {"category": "auth"})

        # Record with a timestamp in the past (beyond the window)
        past = datetime.now(tz=timezone.utc) - timedelta(minutes=2)
        dedup._seen[fp] = past

        assert dedup.should_suppress(fp) is False

    def test_dedup_cleanup(self) -> None:
        """Cleanup removes expired entries."""
        dedup = AlertDeduplicator(suppress_window_minutes=1)
        fp = dedup.fingerprint("rule_a", {"category": "auth"})

        # Insert an expired entry
        past = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        dedup._seen[fp] = past

        removed = dedup.cleanup()
        assert removed == 1
        assert fp not in dedup._seen


# ---------------------------------------------------------------------------
# CLIChannel tests
# ---------------------------------------------------------------------------


class TestCLIChannel:
    async def test_cli_channel_sends(self) -> None:
        """CLIChannel.send() does not crash and returns True."""
        mock_console = MagicMock()
        channel = CLIChannel(console=mock_console)

        alert = Alert.create(
            severity=Severity.HIGH,
            title="Test Alert",
            description="Something happened",
            source_events=["evt-1"],
            rule_name="test_rule",
            mitre_technique="T1110.001",
        )

        result = await channel.send(alert)

        assert result is True
        mock_console.print.assert_called_once()

    async def test_cli_channel_handles_all_severities(self) -> None:
        """CLIChannel correctly handles all severity levels."""
        mock_console = MagicMock()
        channel = CLIChannel(console=mock_console)

        for sev in Severity:
            alert = Alert.create(
                severity=sev,
                title=f"Alert {sev.name}",
                description="desc",
            )
            result = await channel.send(alert)
            assert result is True


# ---------------------------------------------------------------------------
# AlertManager tests
# ---------------------------------------------------------------------------


class TestAlertManager:
    async def test_process_matches_creates_alerts(self) -> None:
        """process_matches converts RuleMatch objects into Alert objects."""
        mock_channel = AsyncMock(spec=AlertChannel)
        mock_channel.send.return_value = True
        dedup = AlertDeduplicator(suppress_window_minutes=15)

        manager = AlertManager(channels=[mock_channel], dedup=dedup)
        match = _make_match()

        alerts = await manager.process_matches([match])

        assert len(alerts) == 1
        assert alerts[0].rule_name == "test_rule"
        assert alerts[0].severity == Severity.HIGH
        assert manager.alert_count == 1

    async def test_alert_manager_sends_to_channels(self) -> None:
        """Alerts are sent to all configured channels."""
        channel1 = AsyncMock(spec=AlertChannel)
        channel1.send.return_value = True
        channel2 = AsyncMock(spec=AlertChannel)
        channel2.send.return_value = True
        dedup = AlertDeduplicator(suppress_window_minutes=15)

        manager = AlertManager(channels=[channel1, channel2], dedup=dedup)
        match = _make_match()

        alerts = await manager.process_matches([match])

        assert len(alerts) == 1
        channel1.send.assert_called_once()
        channel2.send.assert_called_once()

    async def test_process_matches_dedup_suppresses(self) -> None:
        """Duplicate matches with the same fingerprint are suppressed."""
        mock_channel = AsyncMock(spec=AlertChannel)
        mock_channel.send.return_value = True
        dedup = AlertDeduplicator(suppress_window_minutes=15)

        manager = AlertManager(channels=[mock_channel], dedup=dedup)

        # Same rule, same event data -> same fingerprint
        rule = _make_rule(name="dup_rule")
        event = _make_event(category="auth")
        match1 = _make_match(rule=rule, events=[event])
        match2 = _make_match(rule=rule, events=[event])

        alerts1 = await manager.process_matches([match1])
        alerts2 = await manager.process_matches([match2])

        assert len(alerts1) == 1
        assert len(alerts2) == 0  # suppressed
        assert manager.alert_count == 1

    async def test_process_matches_empty(self) -> None:
        """Empty match list produces no alerts."""
        mock_channel = AsyncMock(spec=AlertChannel)
        dedup = AlertDeduplicator()

        manager = AlertManager(channels=[mock_channel], dedup=dedup)
        alerts = await manager.process_matches([])

        assert len(alerts) == 0
        mock_channel.send.assert_not_called()

    async def test_channel_failure_doesnt_break_pipeline(self) -> None:
        """A failing channel doesn't prevent other channels from receiving the alert."""
        failing_channel = AsyncMock(spec=AlertChannel)
        failing_channel.send.side_effect = RuntimeError("Channel down")
        working_channel = AsyncMock(spec=AlertChannel)
        working_channel.send.return_value = True
        dedup = AlertDeduplicator()

        manager = AlertManager(
            channels=[failing_channel, working_channel], dedup=dedup
        )
        match = _make_match()

        alerts = await manager.process_matches([match])

        assert len(alerts) == 1
        working_channel.send.assert_called_once()
