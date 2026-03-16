"""Tests for the PerformanceMonitor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.performance import PerformanceMonitor

if TYPE_CHECKING:
    from guai.core.models import SecurityEvent


def _make_config(
    interval: float = 0.1,
    cpu_threshold: float = 80.0,
    io_threshold_mbps: float = 100.0,
) -> MagicMock:
    config = MagicMock()
    config.monitoring.performance_interval = interval
    config.monitoring.performance_cpu_threshold = cpu_threshold
    config.monitoring.performance_io_threshold_mbps = io_threshold_mbps
    return config


def _make_proc(
    pid: int,
    name: str,
    cpu: float,
    rss: int = 100 * 1024 * 1024,
    read_bytes: int = 0,
    write_bytes: int = 0,
) -> MagicMock:
    """Create a mock psutil process with .info dict."""
    proc = MagicMock()
    mem_info = MagicMock()
    mem_info.rss = rss
    io_info = MagicMock()
    io_info.read_bytes = read_bytes
    io_info.write_bytes = write_bytes
    proc.info = {
        "pid": pid,
        "name": name,
        "cpu_percent": cpu,
        "memory_info": mem_info,
        "io_counters": io_info,
    }
    return proc


class TestPerformanceMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config())
        assert monitor.monitor_type == MonitorType.PERFORMANCE

    def test_initial_health(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config())
        assert monitor.health == ModuleHealth.STOPPED


class TestEmitsProcessEvents:
    @pytest.mark.asyncio
    async def test_emits_events_for_active_processes(self) -> None:
        """Processes above _MIN_CPU_PERCENT should emit events."""
        proc1 = _make_proc(100, "chrome.exe", 25.0)
        proc2 = _make_proc(200, "python.exe", 5.0)

        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc1, proc2]
                monitor._running = False
                return []

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 2
        assert all(e.category == "performance" for e in events)
        assert all(e.source == "performance_monitor" for e in events)
        pids = {e.data["pid"] for e in events}
        assert pids == {100, 200}

    @pytest.mark.asyncio
    async def test_skips_idle_processes(self) -> None:
        """Processes below _MIN_CPU_PERCENT should be skipped."""
        idle_proc = _make_proc(999, "idle.exe", 0.5)

        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [idle_proc]
                monitor._running = False
                return []

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 0


class TestSeverityEscalation:
    @pytest.mark.asyncio
    async def test_high_cpu_is_medium_severity(self) -> None:
        """CPU above threshold should emit MEDIUM severity."""
        proc = _make_proc(100, "heavy.exe", 90.0)

        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config(cpu_threshold=80.0))
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_normal_cpu_is_low_severity(self) -> None:
        """CPU below threshold should emit LOW severity."""
        proc = _make_proc(100, "normal.exe", 10.0)

        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config(cpu_threshold=80.0))
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        assert events[0].severity == Severity.LOW


class TestEventDataFormat:
    @pytest.mark.asyncio
    async def test_event_contains_all_fields(self) -> None:
        proc = _make_proc(
            42, "test.exe", 15.0, rss=200 * 1024 * 1024, read_bytes=1000, write_bytes=2000
        )

        bus = EventBus(max_queue_size=100)
        monitor = PerformanceMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        data = events[0].data
        assert data["pid"] == 42
        assert data["name"] == "test.exe"
        assert data["cpu_percent"] == 15.0
        assert data["ram_mb"] == 200.0
        assert data["io_read_bytes"] == 1000
        assert data["io_write_bytes"] == 2000
        assert "io_delta_read" in data
        assert "io_delta_write" in data
