"""Tests for the LatencyMonitor."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.latency import LatencyMonitor

if TYPE_CHECKING:
    from guai.core.models import SecurityEvent


def _ping_result(
    avg: float | None = None,
    min_: float | None = None,
    max_: float | None = None,
    loss: float = 100.0,
    jitter: float = 0.0,
) -> dict[str, float | None]:
    return {
        "avg_ms": avg,
        "min_ms": min_,
        "max_ms": max_,
        "loss_pct": loss,
        "jitter_ms": jitter,
    }


_STOP_RESULT = _ping_result()

# Sample Windows ping output
_PING_OUTPUT_OK = """\
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=12ms TTL=118
Reply from 8.8.8.8: bytes=32 time=14ms TTL=118
Reply from 8.8.8.8: bytes=32 time=11ms TTL=118

Ping statistics for 8.8.8.8:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 14ms, Average = 12ms
"""

_PING_OUTPUT_LOSS = """\
Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=20ms TTL=64
Request timed out.
Reply from 10.0.0.1: bytes=32 time=25ms TTL=64

Ping statistics for 10.0.0.1:
    Packets: Sent = 3, Received = 2, Lost = 1 (33% loss),
Approximate round trip times in milli-seconds:
    Minimum = 20ms, Maximum = 25ms, Average = 22ms
"""

_PING_OUTPUT_HIGH_JITTER = """\
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=5ms TTL=57
Reply from 1.1.1.1: bytes=32 time=80ms TTL=57
Reply from 1.1.1.1: bytes=32 time=10ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 5ms, Maximum = 80ms, Average = 31ms
"""

_PING_OUTPUT_TOTAL_LOSS = """\
Pinging 192.168.1.1 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"""


def _make_config(
    interval: float = 0.1,
    targets: list[str] | None = None,
    jitter_threshold: float = 50.0,
) -> MagicMock:
    config = MagicMock()
    config.monitoring.latency_interval = interval
    config.monitoring.latency_targets = targets or ["8.8.8.8"]
    config.monitoring.latency_jitter_threshold_ms = jitter_threshold
    return config


def _mock_ping_process(stdout: str) -> AsyncMock:
    """Create a mock subprocess that returns the given stdout."""
    proc = AsyncMock()
    proc.communicate.return_value = (stdout.encode("utf-8"), b"")
    return proc


class TestLatencyMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())
        assert monitor.monitor_type == MonitorType.LATENCY

    def test_initial_health(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())
        assert monitor.health == ModuleHealth.STOPPED


class TestPingParsing:
    @pytest.mark.asyncio
    async def test_parse_normal_ping(self) -> None:
        """Normal ping with no loss should return correct stats."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(_PING_OUTPUT_OK.encode("utf-8"), b""))

        with patch("guai.monitors.latency.asyncio.create_subprocess_exec", return_value=proc):
            result = await monitor._ping("8.8.8.8")

        assert result["avg_ms"] is not None
        assert result["min_ms"] == 11.0
        assert result["max_ms"] == 14.0
        assert result["loss_pct"] == 0.0
        assert result["jitter_ms"] == 3.0

    @pytest.mark.asyncio
    async def test_parse_ping_with_loss(self) -> None:
        """Ping with packet loss should return correct loss percentage."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(_PING_OUTPUT_LOSS.encode("utf-8"), b""))

        with patch("guai.monitors.latency.asyncio.create_subprocess_exec", return_value=proc):
            result = await monitor._ping("10.0.0.1")

        assert result["loss_pct"] == 33.0
        assert result["min_ms"] == 20.0
        assert result["max_ms"] == 25.0

    @pytest.mark.asyncio
    async def test_parse_total_loss(self) -> None:
        """100% packet loss should return None for times."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(_PING_OUTPUT_TOTAL_LOSS.encode("utf-8"), b""))

        with patch("guai.monitors.latency.asyncio.create_subprocess_exec", return_value=proc):
            result = await monitor._ping("192.168.1.1")

        assert result["avg_ms"] is None
        assert result["min_ms"] is None
        assert result["max_ms"] is None
        assert result["loss_pct"] == 100.0


class TestStreamSeverity:
    @pytest.mark.asyncio
    async def test_packet_loss_is_high_severity(self) -> None:
        """Any packet loss should produce HIGH severity event."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config(targets=["10.0.0.1"]))
        monitor._running = True

        events: list[SecurityEvent] = []
        call_count = 0

        async def fake_ping(target: str, count: int = 3) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _ping_result(22.0, 20.0, 25.0, loss=33.0, jitter=5.0)
            monitor._running = False
            return _STOP_RESULT

        monitor._ping = fake_ping  # type: ignore[assignment]

        async for event in monitor.stream():
            events.append(event)

        assert len(events) >= 1
        assert events[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_high_jitter_is_medium_severity(self) -> None:
        """Jitter above threshold with no loss should be MEDIUM severity."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config(targets=["1.1.1.1"], jitter_threshold=50.0))
        monitor._running = True

        events: list[SecurityEvent] = []
        call_count = 0

        async def fake_ping(target: str, count: int = 3) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _ping_result(31.0, 5.0, 80.0, loss=0.0, jitter=75.0)
            monitor._running = False
            return _STOP_RESULT

        monitor._ping = fake_ping  # type: ignore[assignment]

        async for event in monitor.stream():
            events.append(event)

        assert len(events) >= 1
        assert events[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_normal_latency_is_low_severity(self) -> None:
        """Normal ping with no loss and low jitter should be LOW severity."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config(targets=["8.8.8.8"]))
        monitor._running = True

        events: list[SecurityEvent] = []
        call_count = 0

        async def fake_ping(target: str, count: int = 3) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _ping_result(12.0, 11.0, 14.0, loss=0.0, jitter=3.0)
            monitor._running = False
            return _STOP_RESULT

        monitor._ping = fake_ping  # type: ignore[assignment]

        async for event in monitor.stream():
            events.append(event)

        assert len(events) >= 1
        assert events[0].severity == Severity.LOW


class TestStreamEventData:
    @pytest.mark.asyncio
    async def test_event_contains_target_and_metrics(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config(targets=["8.8.8.8"]))
        monitor._running = True

        events: list[SecurityEvent] = []
        call_count = 0

        async def fake_ping(target: str, count: int = 3) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _ping_result(12.3, 11.0, 14.0, loss=0.0, jitter=3.0)
            monitor._running = False
            return _STOP_RESULT

        monitor._ping = fake_ping  # type: ignore[assignment]

        async for event in monitor.stream():
            events.append(event)

        # First event is the real one, second comes from the stopping iteration
        assert len(events) >= 1
        data = events[0].data
        assert data["target"] == "8.8.8.8"
        assert data["avg_ms"] == 12.3
        assert data["min_ms"] == 11.0
        assert data["max_ms"] == 14.0
        assert data["loss_pct"] == 0.0
        assert data["jitter_ms"] == 3.0
        assert events[0].category == "latency"
        assert events[0].source == "latency_monitor"


class TestPingTimeout:
    @pytest.mark.asyncio
    async def test_timeout_returns_full_loss(self) -> None:
        """Timeout on subprocess should return 100% loss."""
        bus = EventBus(max_queue_size=100)
        monitor = LatencyMonitor(bus, _make_config())

        with patch("guai.monitors.latency.asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.return_value = AsyncMock()

            with patch("guai.monitors.latency.asyncio.wait_for", side_effect=TimeoutError):
                result = await monitor._ping("8.8.8.8")

        assert result["avg_ms"] is None
        assert result["loss_pct"] == 100.0
