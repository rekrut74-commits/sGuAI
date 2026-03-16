"""Windows Event Log monitor for GuAI.

Falls back gracefully on non-Windows platforms where win32evtlog
is not available.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)


class EventLogMonitor(BaseMonitor):
    """Monitors Windows Event Log for security-relevant entries.

    Uses ``win32evtlog`` when available (Windows with pywin32 installed).
    On other platforms or when pywin32 is missing the monitor yields
    nothing and sets health to DEGRADED.
    """

    CRITICAL_EVENT_IDS: dict[int, tuple[str, Severity, str]] = {
        # Security log events
        4625: ("auth", Severity.HIGH, "failed_logon"),
        4688: ("process", Severity.MEDIUM, "process_creation"),
        1102: ("security", Severity.CRITICAL, "log_cleared"),
        7045: ("security", Severity.HIGH, "new_service"),
        4697: ("security", Severity.HIGH, "service_install"),
        # System/Application log events (no admin required)
        7036: ("service", Severity.LOW, "service_state_change"),
        7040: ("service", Severity.MEDIUM, "service_start_type_change"),
        1000: ("application", Severity.LOW, "app_error"),
        1001: ("application", Severity.LOW, "app_crash"),
        1022: ("security", Severity.MEDIUM, "msi_install"),
    }

    # Logs to try, in priority order. Security requires admin; others don't.
    _LOG_SOURCES = ["Security", "System", "Application"]

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "event_log_interval", 3.0
        )
        self._win32evtlog: Any = None
        self._available = False
        self._active_logs: list[str] = []
        try:
            import win32evtlog  # type: ignore[import-untyped]

            self._win32evtlog = win32evtlog
            self._available = True
        except ImportError:
            logger.info("win32evtlog not available -- EventLogMonitor will be inactive")

    def _detect_accessible_logs(self) -> list[str]:
        """Probe which event logs we can open without errors."""
        accessible: list[str] = []
        win32evtlog = self._win32evtlog
        for log_name in self._LOG_SOURCES:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                win32evtlog.CloseEventLog(hand)
                accessible.append(log_name)
                logger.info("Event log '%s' is accessible", log_name)
            except Exception:
                logger.info("Event log '%s' not accessible (insufficient privileges)", log_name)
        return accessible

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.EVENT_LOG

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Read Windows Event Log entries.

        Uses win32evtlog if available, otherwise yields nothing.
        All blocking calls are wrapped in ``asyncio.to_thread()``.
        """
        if not self._available or self._win32evtlog is None:
            from guai.core.types import ModuleHealth

            self._health = ModuleHealth.DEGRADED
            logger.warning("EventLogMonitor inactive: win32evtlog not available")
            return

        # Detect which logs are accessible at startup
        self._active_logs = await asyncio.to_thread(self._detect_accessible_logs)
        if not self._active_logs:
            from guai.core.types import ModuleHealth

            self._health = ModuleHealth.DEGRADED
            logger.warning("No event logs accessible -- EventLogMonitor degraded")
            return

        has_security = "Security" in self._active_logs
        if not has_security:
            from guai.core.types import ModuleHealth

            self._health = ModuleHealth.DEGRADED
            logger.warning(
                "Security log not accessible (no admin). Using: %s",
                ", ".join(self._active_logs),
            )

        while self._running:
            try:
                events = await asyncio.to_thread(self._read_events)
                for event in events:
                    yield event
            except Exception:
                logger.exception("Error reading Windows Event Log")

            await asyncio.sleep(self._interval)

    def _read_events(self) -> list[SecurityEvent]:
        """Synchronous helper to read events from accessible logs.

        Returns:
            List of SecurityEvent instances for critical event IDs.
        """
        result: list[SecurityEvent] = []
        win32evtlog = self._win32evtlog

        for log_name in self._active_logs:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = (
                    win32evtlog.EVENTLOG_BACKWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )
                raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
                win32evtlog.CloseEventLog(hand)
            except Exception:
                logger.warning("Failed to read '%s' event log", log_name)
                continue

            for raw in raw_events:
                event_id = raw.EventID & 0xFFFF  # Mask to get actual event ID
                if event_id in self.CRITICAL_EVENT_IDS:
                    category, severity, event_type = self.CRITICAL_EVENT_IDS[event_id]
                    sec_event = SecurityEvent.create(
                        source="event_log_monitor",
                        severity=severity,
                        category=category,
                        data={
                            "event_id": event_id,
                            "event_type": event_type,
                            "log_source": log_name,
                            "source_name": getattr(raw, "SourceName", "unknown"),
                            "time_generated": str(
                                getattr(raw, "TimeGenerated", "unknown")
                            ),
                            "string_inserts": getattr(raw, "StringInserts", None),
                        },
                    )
                    result.append(sec_event)

        return result
