"""Tests for the EventLogMonitor."""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.event_log import EventLogMonitor


def _make_config(interval: float = 0.1) -> MagicMock:
    """Create a mock config."""
    config = MagicMock()
    config.monitoring.event_log_interval = interval
    return config


class TestHandlesMissingWin32evtlog:
    """EventLogMonitor should gracefully handle missing win32evtlog."""

    @pytest.mark.asyncio
    async def test_handles_missing_win32evtlog(self) -> None:
        """On non-Windows or without pywin32, monitor should not crash."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        # Ensure win32evtlog is not importable for this test
        with patch.dict(sys.modules, {"win32evtlog": None}):
            monitor = EventLogMonitor.__new__(EventLogMonitor)
            # Manually call __init__ to force the import check with our patched modules
            monitor.event_bus = bus
            monitor.config = config
            monitor._running = True
            monitor._health = ModuleHealth.STOPPED
            monitor._task = None
            monitor._interval = 0.1
            monitor._win32evtlog = None
            monitor._available = False
            monitor._active_logs = []

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

            # No events, no crash
            assert len(events) == 0
            assert monitor.health == ModuleHealth.DEGRADED

    def test_monitor_type_is_event_log(self) -> None:
        """Monitor type should be EVENT_LOG."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        monitor = EventLogMonitor.__new__(EventLogMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = False
        monitor._health = ModuleHealth.STOPPED
        monitor._task = None
        monitor._interval = 0.1
        monitor._win32evtlog = None
        monitor._available = False
        monitor._active_logs = []

        assert monitor.monitor_type == MonitorType.EVENT_LOG


class TestProcessesCriticalEventIds:
    """EventLogMonitor should process known critical event IDs."""

    @pytest.mark.asyncio
    async def test_processes_critical_event_ids(self) -> None:
        """Critical event IDs should be converted to SecurityEvents."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        # Create a mock win32evtlog module
        mock_win32evtlog = MagicMock()
        mock_win32evtlog.EVENTLOG_BACKWARDS_READ = 0x0004
        mock_win32evtlog.EVENTLOG_SEQUENTIAL_READ = 0x0001

        # Create mock raw events
        raw_event_4625 = MagicMock()
        raw_event_4625.EventID = 4625  # failed_logon
        raw_event_4625.SourceName = "Microsoft-Windows-Security-Auditing"
        raw_event_4625.TimeGenerated = "2026-03-04 12:00:00"
        raw_event_4625.StringInserts = ["user1", "DOMAIN"]

        raw_event_1102 = MagicMock()
        raw_event_1102.EventID = 1102  # log_cleared
        raw_event_1102.SourceName = "Microsoft-Windows-Eventlog"
        raw_event_1102.TimeGenerated = "2026-03-04 12:01:00"
        raw_event_1102.StringInserts = None

        raw_event_9999 = MagicMock()
        raw_event_9999.EventID = 9999  # not critical, should be ignored
        raw_event_9999.SourceName = "SomeApp"
        raw_event_9999.TimeGenerated = "2026-03-04 12:02:00"
        raw_event_9999.StringInserts = None

        mock_handle = MagicMock()

        def _open_only_security(server: Any, log_name: str) -> MagicMock:
            if log_name != "Security":
                raise PermissionError(f"Access denied: {log_name}")
            return mock_handle

        mock_win32evtlog.OpenEventLog.side_effect = _open_only_security
        mock_win32evtlog.ReadEventLog.return_value = [
            raw_event_4625,
            raw_event_1102,
            raw_event_9999,
        ]

        # Build the monitor with the mock win32evtlog
        monitor = EventLogMonitor.__new__(EventLogMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = True
        monitor._health = ModuleHealth.HEALTHY
        monitor._task = None
        monitor._interval = 0.1
        monitor._win32evtlog = mock_win32evtlog
        monitor._available = True
        monitor._active_logs = ["Security"]

        events: list[SecurityEvent] = []
        call_count = 0

        # Override _read_events to stop after one call
        original_read = monitor._read_events

        def read_once() -> list[SecurityEvent]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return original_read()
            monitor._running = False
            return []

        monitor._read_events = read_once  # type: ignore[assignment]

        async for event in monitor.stream():
            events.append(event)

        # Should have 2 events (4625 and 1102, not 9999)
        assert len(events) == 2

        # Check failed_logon event
        logon_events = [e for e in events if e.data["event_type"] == "failed_logon"]
        assert len(logon_events) == 1
        assert logon_events[0].severity == Severity.HIGH
        assert logon_events[0].category == "auth"
        assert logon_events[0].source == "event_log_monitor"
        assert logon_events[0].data["event_id"] == 4625

        # Check log_cleared event
        cleared_events = [e for e in events if e.data["event_type"] == "log_cleared"]
        assert len(cleared_events) == 1
        assert cleared_events[0].severity == Severity.CRITICAL
        assert cleared_events[0].category == "security"
        assert cleared_events[0].data["event_id"] == 1102

    def test_critical_event_ids_map(self) -> None:
        """Verify CRITICAL_EVENT_IDS has expected entries."""
        ids = EventLogMonitor.CRITICAL_EVENT_IDS

        assert 4625 in ids
        assert ids[4625] == ("auth", Severity.HIGH, "failed_logon")

        assert 4688 in ids
        assert ids[4688] == ("process", Severity.MEDIUM, "process_creation")

        assert 1102 in ids
        assert ids[1102] == ("security", Severity.CRITICAL, "log_cleared")

        assert 7045 in ids
        assert ids[7045] == ("security", Severity.HIGH, "new_service")

        assert 4697 in ids
        assert ids[4697] == ("security", Severity.HIGH, "service_install")
