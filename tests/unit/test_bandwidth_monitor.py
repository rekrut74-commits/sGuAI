"""Tests for the BandwidthMonitor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.bandwidth import BandwidthMonitor

if TYPE_CHECKING:
    from guai.core.models import SecurityEvent


def _make_config(
    interval: float = 0.1,
    drop_threshold_pct: float = 50.0,
) -> MagicMock:
    config = MagicMock()
    config.monitoring.bandwidth_interval = interval
    config.monitoring.bandwidth_drop_threshold_pct = drop_threshold_pct
    return config


def _make_net_stats(
    bytes_recv: int = 1000,
    bytes_sent: int = 500,
    errin: int = 0,
    errout: int = 0,
    dropin: int = 0,
    dropout: int = 0,
) -> MagicMock:
    stats = MagicMock()
    stats.bytes_recv = bytes_recv
    stats.bytes_sent = bytes_sent
    stats.errin = errin
    stats.errout = errout
    stats.dropin = dropin
    stats.dropout = dropout
    return stats


class TestBandwidthMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        assert monitor.monitor_type == MonitorType.BANDWIDTH

    def test_initial_health(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        assert monitor.health == ModuleHealth.STOPPED


class TestSkipsFirstSample:
    @pytest.mark.asyncio
    async def test_no_events_on_first_sample(self) -> None:
        """First sample is baseline only — no events emitted."""
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return {"Ethernet": _make_net_stats(1000, 500)}
                monitor._running = False
                return {}

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 0


class TestEmitsBandwidthEvents:
    @pytest.mark.asyncio
    async def test_emits_events_on_second_sample(self) -> None:
        """Second sample should calculate delta and emit event."""
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return {"Ethernet": _make_net_stats(1000, 500)}
                if call_count == 2:
                    return {"Ethernet": _make_net_stats(2000, 1000)}
                monitor._running = False
                return {}

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        assert events[0].category == "bandwidth"
        assert events[0].source == "bandwidth_monitor"
        assert events[0].data["interface"] == "Ethernet"
        assert events[0].data["throughput_in_kbps"] > 0


class TestSkipsLoopback:
    @pytest.mark.asyncio
    async def test_loopback_is_skipped(self) -> None:
        """Loopback interfaces should not produce events."""
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    return {
                        "Loopback Pseudo-Interface 1": _make_net_stats(1000 * call_count, 500),
                        "lo": _make_net_stats(1000 * call_count, 500),
                    }
                monitor._running = False
                return {}

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 0


class TestSeverityOnThroughputDrop:
    @pytest.mark.asyncio
    async def test_normal_throughput_is_low_severity(self) -> None:
        """Stable throughput should emit LOW severity."""
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return {"Ethernet": _make_net_stats(10000, 5000)}
                if call_count == 2:
                    return {"Ethernet": _make_net_stats(20000, 10000)}
                monitor._running = False
                return {}

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        assert events[0].severity == Severity.LOW


class TestEventDataFields:
    @pytest.mark.asyncio
    async def test_data_contains_expected_keys(self) -> None:
        bus = EventBus(max_queue_size=100)
        monitor = BandwidthMonitor(bus, _make_config())
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.asyncio.to_thread") as mock_thread:
            call_count = 0

            async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return {"WiFi": _make_net_stats(5000, 2000, errin=1, dropin=2)}
                if call_count == 2:
                    return {"WiFi": _make_net_stats(15000, 8000, errin=3, dropin=5)}
                monitor._running = False
                return {}

            mock_thread.side_effect = fake_to_thread

            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        data = events[0].data
        expected_keys = {
            "interface",
            "throughput_in_kbps",
            "throughput_out_kbps",
            "avg_in_kbps",
            "avg_out_kbps",
            "errors_in",
            "errors_out",
            "drops_in",
            "drops_out",
        }
        assert expected_keys.issubset(data.keys())
        assert data["interface"] == "WiFi"
        assert data["errors_in"] == 3
        assert data["drops_in"] == 5
