"""Tests for guai.mcp.tools — time parsing and data formatting helpers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from guai.mcp.tools import format_alerts, format_events, parse_since


# ---------- parse_since ----------


class TestParseSinceHours:
    """parse_since with hour-based inputs."""

    def test_1h(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("1h")
        # Should be approximately 1 hour ago (within 2 seconds tolerance)
        expected = now - timedelta(hours=1)
        assert abs((result - expected).total_seconds()) < 2

    def test_24h(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("24h")
        expected = now - timedelta(hours=24)
        assert abs((result - expected).total_seconds()) < 2

    def test_uppercase_H(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("2H")
        expected = now - timedelta(hours=2)
        assert abs((result - expected).total_seconds()) < 2


class TestParseSinceDays:
    """parse_since with day-based inputs."""

    def test_1d(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("1d")
        expected = now - timedelta(days=1)
        assert abs((result - expected).total_seconds()) < 2

    def test_7d(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("7d")
        expected = now - timedelta(days=7)
        assert abs((result - expected).total_seconds()) < 2

    def test_30d(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("30d")
        expected = now - timedelta(days=30)
        assert abs((result - expected).total_seconds()) < 2


class TestParseSinceMinutes:
    """parse_since with minute-based inputs."""

    def test_30m(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("30m")
        expected = now - timedelta(minutes=30)
        assert abs((result - expected).total_seconds()) < 2

    def test_5m(self) -> None:
        now = datetime.now(timezone.utc)
        result = parse_since("5m")
        expected = now - timedelta(minutes=5)
        assert abs((result - expected).total_seconds()) < 2


class TestParseSinceInvalid:
    """parse_since should raise ValueError for invalid inputs."""

    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("")

    def test_no_unit(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("42")

    def test_invalid_unit(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("5x")

    def test_negative(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("-1h")

    def test_float(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("1.5h")

    def test_words(self) -> None:
        with pytest.raises(ValueError, match="Invalid 'since' format"):
            parse_since("one hour")


# ---------- format_events ----------


class TestFormatEvents:
    """format_events should produce valid JSON with count."""

    def test_empty_list(self) -> None:
        result = format_events([])
        data = json.loads(result)
        assert data["events"] == []
        assert data["count"] == 0

    def test_single_event(self) -> None:
        events = [
            {
                "event_id": "ev-1",
                "timestamp": "2025-06-01T12:00:00Z",
                "source": "sysmon",
                "severity": 7,
                "category": "process",
                "data": '{"pid": 1234}',
            }
        ]
        result = format_events(events)
        data = json.loads(result)
        assert data["count"] == 1
        assert len(data["events"]) == 1
        assert data["events"][0]["event_id"] == "ev-1"

    def test_multiple_events(self) -> None:
        events = [
            {"event_id": f"ev-{i}", "severity": i} for i in range(5)
        ]
        result = format_events(events)
        data = json.loads(result)
        assert data["count"] == 5
        assert len(data["events"]) == 5


# ---------- format_alerts ----------


class TestFormatAlerts:
    """format_alerts should produce valid JSON with count."""

    def test_empty_list(self) -> None:
        result = format_alerts([])
        data = json.loads(result)
        assert data["alerts"] == []
        assert data["count"] == 0

    def test_single_alert(self) -> None:
        alerts = [
            {
                "alert_id": "alert-1",
                "timestamp": "2025-06-01T12:00:00Z",
                "severity": 3,
                "title": "Suspicious process",
                "description": "Detected suspicious activity",
                "status": "new",
            }
        ]
        result = format_alerts(alerts)
        data = json.loads(result)
        assert data["count"] == 1
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["alert_id"] == "alert-1"
        assert data["alerts"][0]["status"] == "new"

    def test_multiple_alerts(self) -> None:
        alerts = [
            {"alert_id": f"alert-{i}", "severity": i, "status": "new"}
            for i in range(3)
        ]
        result = format_alerts(alerts)
        data = json.loads(result)
        assert data["count"] == 3
        assert len(data["alerts"]) == 3
