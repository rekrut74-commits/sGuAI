"""Tests for the ProcessMonitor."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.process import SUSPICIOUS_PARENTS, ProcessMonitor


def _make_proc(
    pid: int = 1000,
    name: str = "test.exe",
    cmdline: list[str] | None = None,
    ppid: int | None = 1,
) -> MagicMock:
    """Create a mock psutil process with .info dict."""
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": name,
        "cmdline": cmdline or [name],
        "ppid": ppid,
    }
    return proc


def _make_config(interval: float = 0.1) -> MagicMock:
    """Create a mock config."""
    config = MagicMock()
    config.monitoring.process_interval = interval
    return config


class TestDetectsNewProcess:
    """ProcessMonitor should emit events for newly appearing processes."""

    @pytest.mark.asyncio
    async def test_detects_new_process(self) -> None:
        """A process not in _known_pids should generate an event."""
        proc = _make_proc(pid=42, name="notepad.exe", ppid=1)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = ProcessMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.process.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: Any = None) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        event = events[0]
        assert event.source == "process_monitor"
        assert event.category == "process"
        assert event.data["pid"] == 42
        assert event.data["name"] == "notepad.exe"


class TestDetectsSuspiciousParentChild:
    """Suspicious parent-child pairs should yield HIGH severity."""

    @pytest.mark.asyncio
    async def test_detects_suspicious_parent_child(self) -> None:
        """cmd.exe spawned by WINWORD.EXE should get HIGH severity."""
        parent = _make_proc(pid=100, name="WINWORD.EXE", ppid=1)
        child = _make_proc(pid=200, name="cmd.exe", ppid=100)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = ProcessMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.process.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: Any = None) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [parent, child]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            async for event in monitor.stream():
                events.append(event)

        # Find the child event (cmd.exe)
        child_events = [e for e in events if e.data["name"] == "cmd.exe"]
        assert len(child_events) == 1
        assert child_events[0].severity == Severity.HIGH
        assert child_events[0].data["parent_name"] == "WINWORD.EXE"

        # Parent (WINWORD.EXE) should be LOW
        parent_events = [e for e in events if e.data["name"] == "WINWORD.EXE"]
        assert len(parent_events) == 1
        assert parent_events[0].severity == Severity.LOW


class TestIgnoresKnownProcesses:
    """Processes already in _known_pids should not generate events."""

    @pytest.mark.asyncio
    async def test_ignores_known_processes(self) -> None:
        """Same PID in second snapshot should not produce a second event."""
        proc = _make_proc(pid=42, name="notepad.exe", ppid=1)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = ProcessMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.process.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: Any = None) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    return [proc]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            async for event in monitor.stream():
                events.append(event)

        # Only 1 event from first snapshot
        assert len(events) == 1


class TestMonitorType:
    """ProcessMonitor should report correct monitor_type."""

    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = ProcessMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.PROCESS


class TestSuspiciousParentsConstant:
    """Verify the SUSPICIOUS_PARENTS dict contains expected entries."""

    def test_suspicious_parents_contains_winword(self) -> None:
        assert "WINWORD.EXE" in SUSPICIOUS_PARENTS
        assert "cmd.exe" in SUSPICIOUS_PARENTS["WINWORD.EXE"]
        assert "powershell.exe" in SUSPICIOUS_PARENTS["WINWORD.EXE"]

    def test_suspicious_parents_contains_excel(self) -> None:
        assert "EXCEL.EXE" in SUSPICIOUS_PARENTS
        assert "cmd.exe" in SUSPICIOUS_PARENTS["EXCEL.EXE"]

    def test_suspicious_parents_contains_outlook(self) -> None:
        assert "OUTLOOK.EXE" in SUSPICIOUS_PARENTS
        assert "cmd.exe" in SUSPICIOUS_PARENTS["OUTLOOK.EXE"]

    def test_suspicious_parents_contains_svchost(self) -> None:
        assert "svchost.exe" in SUSPICIOUS_PARENTS
        assert "powershell.exe" in SUSPICIOUS_PARENTS["svchost.exe"]
