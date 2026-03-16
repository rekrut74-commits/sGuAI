"""Tests for the NetworkMonitor."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.network import NetworkMonitor


def _make_conn(
    laddr: tuple[str, int] | None = ("127.0.0.1", 8080),
    raddr: tuple[str, int] | None = ("10.0.0.1", 443),
    status: str = "ESTABLISHED",
    pid: int | None = 1234,
) -> MagicMock:
    """Create a mock psutil connection object."""
    conn = MagicMock()
    if laddr:
        conn.laddr = MagicMock(ip=laddr[0], port=laddr[1])
    else:
        conn.laddr = None
    if raddr:
        conn.raddr = MagicMock(ip=raddr[0], port=raddr[1])
    else:
        conn.raddr = None
    conn.status = status
    conn.pid = pid
    return conn


def _make_config(interval: float = 0.1) -> MagicMock:
    """Create a mock config with monitoring.network_interval."""
    config = MagicMock()
    config.monitoring.network_interval = interval
    return config


class TestDetectsNewConnections:
    """NetworkMonitor should emit events for new connections."""

    @pytest.mark.asyncio
    async def test_detects_new_connections(self) -> None:
        """New connections in the first snapshot should produce events."""
        conn1 = _make_conn(("127.0.0.1", 8080), ("10.0.0.1", 443), "ESTABLISHED", 100)
        conn2 = _make_conn(("127.0.0.1", 9090), ("10.0.0.2", 80), "ESTABLISHED", 200)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.network.psutil") as mock_psutil:
            call_count = 0

            def fake_net_connections() -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [conn1, conn2]
                # Stop after first iteration
                monitor._running = False
                return []

            mock_psutil.net_connections = fake_net_connections

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 2
        assert all(e.category == "network" for e in events)
        assert all(e.source == "network_monitor" for e in events)
        # Verify data fields
        addrs = {e.data["remote_addr"] for e in events}
        assert "10.0.0.1:443" in addrs
        assert "10.0.0.2:80" in addrs


class TestIgnoresExistingConnections:
    """Connections seen in the previous snapshot should not produce events."""

    @pytest.mark.asyncio
    async def test_ignores_existing_connections(self) -> None:
        """Second snapshot with same connections should not emit new events."""
        conn1 = _make_conn(("127.0.0.1", 8080), ("10.0.0.1", 443), "ESTABLISHED", 100)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.network.psutil") as mock_psutil:
            call_count = 0

            def fake_net_connections() -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    return [conn1]
                monitor._running = False
                return []

            mock_psutil.net_connections = fake_net_connections

            async for event in monitor.stream():
                events.append(event)

        # Only 1 event from the first snapshot, not 2
        assert len(events) == 1


class TestUsesAsyncThread:
    """NetworkMonitor should use asyncio.to_thread for psutil calls."""

    @pytest.mark.asyncio
    async def test_uses_async_thread(self) -> None:
        """Verify asyncio.to_thread is called for net_connections."""
        conn1 = _make_conn()

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        monitor._running = True

        with patch("guai.monitors.network.asyncio.to_thread") as mock_to_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [conn1]
                monitor._running = False
                return []

            mock_to_thread.side_effect = fake_to_thread

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

            assert mock_to_thread.call_count >= 1


class TestEmitsCorrectEventFormat:
    """Events must have the expected structure."""

    @pytest.mark.asyncio
    async def test_emits_correct_event_format(self) -> None:
        """Each event should have correct source, category, severity, and data keys."""
        conn = _make_conn(("192.168.1.1", 5555), ("8.8.8.8", 53), "ESTABLISHED", 999)

        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        monitor._running = True

        with patch("guai.monitors.network.psutil") as mock_psutil:
            call_count = 0

            def fake_net_connections() -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [conn]
                monitor._running = False
                return []

            mock_psutil.net_connections = fake_net_connections

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        event = events[0]

        assert event.source == "network_monitor"
        assert event.category == "network"
        assert event.severity == Severity.LOW
        assert event.data["local_addr"] == "192.168.1.1:5555"
        assert event.data["remote_addr"] == "8.8.8.8:53"
        assert event.data["status"] == "ESTABLISHED"
        assert event.data["pid"] == 999
        assert event.event_id  # non-empty
        assert event.timestamp  # non-None


class TestMonitorType:
    """NetworkMonitor should report correct monitor_type."""

    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.NETWORK


class TestHealthLifecycle:
    """Monitor health transitions."""

    def test_initial_health_is_stopped(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = NetworkMonitor(bus, config)
        assert monitor.health == ModuleHealth.STOPPED
