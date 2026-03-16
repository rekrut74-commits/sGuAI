"""Tests for the WiFiMonitor."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.wifi import WiFiMonitor

SAMPLE_NETSH_OUTPUT = """\
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 85%
         Radio type         : 802.11ac
         Channel            : 6

SSID 2 : OpenCafe
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:02
         Signal             : 45%
         Radio type         : 802.11n
         Channel            : 11

SSID 3 : CorpWiFi
    Network type            : Infrastructure
    Authentication          : WPA3-Enterprise
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:03
         Signal             : 70%
         Radio type         : 802.11ax
         Channel            : 36
    BSSID 2                 : aa:bb:cc:dd:ee:04
         Signal             : 55%
         Radio type         : 802.11ax
         Channel            : 40
"""


def _make_config(interval: float = 0.1) -> MagicMock:
    config = MagicMock()
    config.monitoring.wifi_interval = interval
    return config


class TestWiFiMonitorType:
    def test_monitor_type_is_wifi(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.WIFI


class TestParseNetworks:
    def test_parses_multiple_networks(self) -> None:
        networks = WiFiMonitor._parse_networks(SAMPLE_NETSH_OUTPUT)
        # 3 SSIDs but CorpWiFi has 2 BSSIDs = 4 entries total
        assert len(networks) == 4

    def test_extracts_ssid_bssid_signal_auth(self) -> None:
        networks = WiFiMonitor._parse_networks(SAMPLE_NETSH_OUTPUT)
        home = [n for n in networks if n["ssid"] == "HomeNetwork"]
        assert len(home) == 1
        assert home[0]["bssid"] == "aa:bb:cc:dd:ee:01"
        assert home[0]["signal"] == "85%"
        assert home[0]["auth"] == "WPA2-Personal"
        assert home[0]["channel"] == "6"

    def test_detects_open_network(self) -> None:
        networks = WiFiMonitor._parse_networks(SAMPLE_NETSH_OUTPUT)
        cafe = [n for n in networks if n["ssid"] == "OpenCafe"]
        assert len(cafe) == 1
        assert cafe[0]["auth"] == "Open"

    def test_multiple_bssids_per_ssid(self) -> None:
        networks = WiFiMonitor._parse_networks(SAMPLE_NETSH_OUTPUT)
        corp = [n for n in networks if n["ssid"] == "CorpWiFi"]
        assert len(corp) == 2
        bssids = {n["bssid"] for n in corp}
        assert bssids == {"aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:04"}

    def test_empty_output(self) -> None:
        networks = WiFiMonitor._parse_networks("")
        assert networks == []


class TestParseInterface:
    def test_parses_connected_interface(self) -> None:
        output = """\
    Name                   : Wi-Fi
    SSID                   : MyHome
    BSSID                  : aa:bb:cc:dd:ee:ff
    Signal                 : 90%
    Channel                : 6
    Authentication         : WPA2-Personal
    State                  : connected
"""
        result = WiFiMonitor._parse_interface(output)
        assert result is not None
        assert result["ssid"] == "MyHome"
        assert result["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert result["signal"] == "90%"
        assert result["auth"] == "WPA2-Personal"

    def test_returns_none_when_disconnected(self) -> None:
        output = """\
    Name                   : Wi-Fi
    State                  : disconnected
"""
        result = WiFiMonitor._parse_interface(output)
        assert result is None


class TestWiFiStream:
    @pytest.mark.asyncio
    async def test_emits_new_network_events(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        monitor._running = True

        call_count = 0

        def mock_netsh() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # probe + first iteration
                return SAMPLE_NETSH_OUTPUT
            monitor._running = False
            return SAMPLE_NETSH_OUTPUT

        with (
            patch.object(WiFiMonitor, "_has_wifi_adapter", return_value=True),
            patch.object(WiFiMonitor, "_run_netsh_networks", side_effect=mock_netsh),
        ):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        # 4 BSSIDs = 4 new_network/open_network events
        assert len(events) == 4

        # Check open network has MEDIUM severity
        open_events = [e for e in events if e.data["event_type"] == "open_network"]
        assert len(open_events) == 1
        assert open_events[0].severity == Severity.MEDIUM
        assert open_events[0].data["ssid"] == "OpenCafe"

        # Other networks should be LOW
        new_events = [e for e in events if e.data["event_type"] == "new_network"]
        assert len(new_events) == 3
        for ev in new_events:
            assert ev.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_handles_no_adapter(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        monitor._running = True

        with patch.object(WiFiMonitor, "_has_wifi_adapter", return_value=False):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 0
        assert monitor.health == ModuleHealth.DEGRADED

    @pytest.mark.asyncio
    async def test_fallback_to_interfaces_mode(self) -> None:
        """When show networks fails, falls back to show interfaces."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        monitor._running = True

        interface_output = """\
    Name                   : Wi-Fi
    SSID                   : FallbackNet
    BSSID                  : 11:22:33:44:55:66
    Signal                 : 75%
    Channel                : 11
    Authentication         : WPA2-Personal
    State                  : connected
"""
        call_count = 0

        def mock_interfaces() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return interface_output
            monitor._running = False
            return interface_output

        with (
            patch.object(WiFiMonitor, "_has_wifi_adapter", return_value=True),
            patch.object(WiFiMonitor, "_run_netsh_networks", return_value=None),
            patch.object(WiFiMonitor, "_run_netsh_interfaces", side_effect=mock_interfaces),
        ):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 1
        assert events[0].data["event_type"] == "wifi_connected"
        assert events[0].data["ssid"] == "FallbackNet"
        assert monitor.health == ModuleHealth.DEGRADED  # degraded due to interfaces-only mode

    @pytest.mark.asyncio
    async def test_delta_detection_no_duplicates(self) -> None:
        """Second scan with same networks should produce no new events."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        monitor._running = True

        call_count = 0

        def mock_netsh() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # probe + 2 iterations
                return SAMPLE_NETSH_OUTPUT
            monitor._running = False
            return SAMPLE_NETSH_OUTPUT

        with (
            patch.object(WiFiMonitor, "_has_wifi_adapter", return_value=True),
            patch.object(WiFiMonitor, "_run_netsh_networks", side_effect=mock_netsh),
        ):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        # Only first scan should produce events (4), second scan = 0 new
        assert len(events) == 4

    @pytest.mark.asyncio
    async def test_disappeared_network(self) -> None:
        """Networks that disappear between scans emit disappear events."""
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = WiFiMonitor(bus, config)
        monitor._running = True

        call_count = 0

        def mock_netsh() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # probe
                return SAMPLE_NETSH_OUTPUT
            if call_count == 2:  # first scan — networks visible
                return SAMPLE_NETSH_OUTPUT
            if call_count == 3:  # second scan — all gone
                return ""
            monitor._running = False
            return ""

        with (
            patch.object(WiFiMonitor, "_has_wifi_adapter", return_value=True),
            patch.object(WiFiMonitor, "_run_netsh_networks", side_effect=mock_netsh),
        ):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        new_events = [e for e in events if e.data["event_type"] != "network_disappeared"]
        disappeared = [e for e in events if e.data["event_type"] == "network_disappeared"]

        assert len(new_events) == 4  # first scan
        assert len(disappeared) == 4  # all 4 BSSIDs disappeared
