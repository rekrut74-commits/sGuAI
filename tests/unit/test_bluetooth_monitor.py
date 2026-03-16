"""Tests for the BluetoothMonitor."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.bluetooth import BluetoothMonitor


def _make_config(interval: float = 0.1) -> MagicMock:
    config = MagicMock()
    config.monitoring.bluetooth_interval = interval
    return config


def _make_adv_result(
    devices: list[tuple[str, str, int]],
) -> dict[str, tuple[MagicMock, MagicMock]]:
    """Create a dict[addr, (BLEDevice, AdvertisementData)] for return_adv=True."""
    result: dict[str, tuple[MagicMock, MagicMock]] = {}
    for name, address, rssi in devices:
        dev = MagicMock()
        dev.name = name
        dev.address = address
        adv = MagicMock()
        adv.rssi = rssi
        result[address] = (dev, adv)
    return result


class TestBluetoothMonitorType:
    def test_monitor_type_is_bluetooth(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        monitor = BluetoothMonitor.__new__(BluetoothMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = False
        monitor._health = ModuleHealth.STOPPED
        monitor._task = None
        monitor._interval = 0.1
        monitor._known_devices = set()
        monitor._bleak = None
        monitor._available = False

        assert monitor.monitor_type == MonitorType.BLUETOOTH


class TestHandlesMissingBleak:
    @pytest.mark.asyncio
    async def test_degraded_without_bleak(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        monitor = BluetoothMonitor.__new__(BluetoothMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = True
        monitor._health = ModuleHealth.STOPPED
        monitor._task = None
        monitor._interval = 0.1
        monitor._known_devices = set()
        monitor._bleak = None
        monitor._available = False

        events: list[SecurityEvent] = []
        async for event in monitor.stream():
            events.append(event)

        assert len(events) == 0
        assert monitor.health == ModuleHealth.DEGRADED


class TestBluetoothStream:
    @pytest.mark.asyncio
    async def test_emits_new_device_events(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        adv_result = _make_adv_result([
            ("HeadphonesXM5", "AA:BB:CC:DD:EE:01", -40),
            ("SmartWatch", "AA:BB:CC:DD:EE:02", -65),
        ])

        mock_bleak = MagicMock()
        call_count = 0

        async def mock_discover(
            timeout: float = 5.0, return_adv: bool = False
        ) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # probe + first scan
                return adv_result
            monitor._running = False
            return adv_result

        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakScanner.discover = mock_discover

        monitor = BluetoothMonitor.__new__(BluetoothMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = True
        monitor._health = ModuleHealth.HEALTHY
        monitor._task = None
        monitor._interval = 0.1
        monitor._known_devices = set()
        monitor._bleak = mock_bleak
        monitor._available = True

        events: list[SecurityEvent] = []
        async for event in monitor.stream():
            events.append(event)

        assert len(events) == 2

        new_events = [e for e in events if e.data["event_type"] == "new_device"]
        assert len(new_events) == 2

        names = {e.data["name"] for e in new_events}
        assert names == {"HeadphonesXM5", "SmartWatch"}

        for ev in new_events:
            assert ev.severity == Severity.LOW
            assert ev.category == "bluetooth"
            assert ev.source == "bluetooth_monitor"
            assert ev.data["rssi"] is not None

    @pytest.mark.asyncio
    async def test_delta_no_duplicates(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        adv_result = _make_adv_result([("Device1", "AA:BB:CC:DD:EE:01", -50)])

        mock_bleak = MagicMock()
        call_count = 0

        async def mock_discover(
            timeout: float = 5.0, return_adv: bool = False
        ) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # probe + 2 scans
                return adv_result
            monitor._running = False
            return adv_result

        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakScanner.discover = mock_discover

        monitor = BluetoothMonitor.__new__(BluetoothMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = True
        monitor._health = ModuleHealth.HEALTHY
        monitor._task = None
        monitor._interval = 0.1
        monitor._known_devices = set()
        monitor._bleak = mock_bleak
        monitor._available = True

        events: list[SecurityEvent] = []
        async for event in monitor.stream():
            events.append(event)

        # Only first scan produces events
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_disappeared_device(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()

        adv_result = _make_adv_result([("Device1", "AA:BB:CC:DD:EE:01", -50)])
        empty_result: dict[str, tuple[MagicMock, MagicMock]] = {}

        mock_bleak = MagicMock()
        call_count = 0

        async def mock_discover(
            timeout: float = 5.0, return_adv: bool = False
        ) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # probe + first scan
                return adv_result
            if call_count == 3:  # second scan = empty
                return empty_result
            monitor._running = False
            return empty_result

        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakScanner.discover = mock_discover

        monitor = BluetoothMonitor.__new__(BluetoothMonitor)
        monitor.event_bus = bus
        monitor.config = config
        monitor._running = True
        monitor._health = ModuleHealth.HEALTHY
        monitor._task = None
        monitor._interval = 0.1
        monitor._known_devices = set()
        monitor._bleak = mock_bleak
        monitor._available = True

        events: list[SecurityEvent] = []
        async for event in monitor.stream():
            events.append(event)

        new_events = [e for e in events if e.data["event_type"] == "new_device"]
        disappeared = [e for e in events if e.data["event_type"] == "device_disappeared"]

        assert len(new_events) == 1
        assert len(disappeared) == 1
        assert disappeared[0].data["address"] == "aa:bb:cc:dd:ee:01"
