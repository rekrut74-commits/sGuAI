"""Tests for the DNSMonitor."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.dns import DNSMonitor, _shannon_entropy

SAMPLE_IPCONFIG_OUTPUT = """\
Windows IP Configuration

    Record Name . . . . . : google.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 250
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 142.250.80.46

    Record Name . . . . . : github.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 60
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 140.82.121.3

    Record Name . . . . . : xn--a1b2c3d4e5f6g7h8i9.suspicious-very-long-domain-that-looks-like-dga-generated.example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 30
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 1.2.3.4
"""


def _make_config(interval: float = 0.1) -> MagicMock:
    config = MagicMock()
    config.monitoring.dns_interval = interval
    return config


class TestDNSMonitorType:
    def test_monitor_type_is_dns(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = DNSMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.DNS


class TestParseDNSCache:
    def test_parses_records(self) -> None:
        records = DNSMonitor._parse_dns_cache(SAMPLE_IPCONFIG_OUTPUT)
        assert len(records) == 3

        google = [r for r in records if r["domain"] == "google.com"]
        assert len(google) == 1
        assert google[0]["record_type"] == "A"
        assert google[0]["data"] == "142.250.80.46"
        assert google[0]["ttl"] == "250"

    def test_empty_output(self) -> None:
        records = DNSMonitor._parse_dns_cache("")
        assert records == []


class TestSuspiciousDomain:
    def test_short_domain_not_suspicious(self) -> None:
        assert not DNSMonitor._is_suspicious("google.com")

    def test_long_domain_suspicious(self) -> None:
        long_domain = "a" * 51 + ".example.com"
        assert DNSMonitor._is_suspicious(long_domain)

    def test_high_entropy_domain_suspicious(self) -> None:
        # Random-looking subdomain
        dga_domain = "x8k4m2n9p3q7r1s5t6u0v.evil.com"
        # This has high entropy and is > 20 chars in host part
        assert DNSMonitor._is_suspicious(dga_domain)

    def test_short_dga_domain_flagged(self) -> None:
        # Short random-looking domains with few vowels (DGA pattern)
        assert DNSMonitor._is_suspicious("njtzzrvg0lwj3bsn.info")
        assert DNSMonitor._is_suspicious("qwrtypsdfghjkl.net")

    def test_cdn_hash_not_suspicious(self) -> None:
        # CDN subdomains with short hash labels should not flag
        assert not DNSMonitor._is_suspicious("e83157.dscb.akamaiedge.net")

    def test_normal_domain_not_suspicious(self) -> None:
        assert not DNSMonitor._is_suspicious("mail.google.com")
        assert not DNSMonitor._is_suspicious("cdn.cloudflare.net")
        assert not DNSMonitor._is_suspicious("api.githubcopilot.com")


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert _shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self) -> None:
        # All unique chars = high entropy
        e = _shannon_entropy("abcdefghijklmnop")
        assert e > 3.5

    def test_low_entropy(self) -> None:
        e = _shannon_entropy("aaaaab")
        assert e < 1.0


class TestDNSStream:
    @pytest.mark.asyncio
    async def test_emits_new_dns_events(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = DNSMonitor(bus, config)
        monitor._running = True

        call_count = 0

        def mock_ipconfig() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # probe + first iteration
                return SAMPLE_IPCONFIG_OUTPUT
            monitor._running = False
            return SAMPLE_IPCONFIG_OUTPUT

        with patch.object(DNSMonitor, "_run_ipconfig", side_effect=mock_ipconfig):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 3

        # google.com and github.com = new_dns_record (LOW)
        normal = [e for e in events if e.data["event_type"] == "new_dns_record"]
        assert len(normal) == 2

        # Long DGA-like domain = suspicious_domain (MEDIUM)
        suspicious = [e for e in events if e.data["event_type"] == "suspicious_domain"]
        assert len(suspicious) == 1
        assert suspicious[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_handles_unavailable_ipconfig(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = DNSMonitor(bus, config)
        monitor._running = True

        with patch.object(DNSMonitor, "_run_ipconfig", return_value=None):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) == 0
        assert monitor.health == ModuleHealth.DEGRADED

    @pytest.mark.asyncio
    async def test_delta_no_duplicates(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = DNSMonitor(bus, config)
        monitor._running = True

        call_count = 0

        def mock_ipconfig() -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # probe + 2 iterations
                return SAMPLE_IPCONFIG_OUTPUT
            monitor._running = False
            return SAMPLE_IPCONFIG_OUTPUT

        with patch.object(DNSMonitor, "_run_ipconfig", side_effect=mock_ipconfig):
            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        # Only first scan produces events
        assert len(events) == 3
