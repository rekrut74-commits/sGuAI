# Performance Monitors Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Dodac monitory wydajnosciowe do GuAI: per-process CPU/RAM/IO, bandwidth per interface, latency/jitter, VPN health — generyczne, bez hardcode na konkretne procesy.

**Architecture:** 3 nowe monitory dziedziczace z BaseMonitor, kazdy emituje SecurityEvent przez EventBus. PerformanceMonitor trackuje trendy per-process (delta CPU, delta IO). BandwidthMonitor mierzy throughput per interface. LatencyMonitor mierzy ping/jitter do konfigurowalnych endpointow. Nowe reguly YAML wyzwalaja alerty na anomalie.

**Tech Stack:** psutil (CPU, IO, net_io_counters), asyncio subprocess (ping), istniejacy BaseMonitor/EventBus/RuleEngine.

---

## Task 1: Rozszerzenie typow i konfiguracji

**Files:**
- Modify: `src/guai/core/types.py`
- Modify: `src/guai/core/config.py`
- Test: `tests/unit/test_config.py`

**Step 1: Write failing test**

```python
# tests/unit/test_config.py — dopisac na koncu pliku

class TestPerformanceConfig:
    def test_performance_monitor_defaults(self) -> None:
        from guai.core.config import GuAIConfig
        config = GuAIConfig()
        assert config.monitoring.performance_interval == 5.0
        assert config.monitoring.bandwidth_interval == 5.0
        assert config.monitoring.latency_interval == 10.0
        assert config.monitoring.latency_targets == ["8.8.8.8", "1.1.1.1"]
        assert config.monitoring.performance_cpu_threshold == 80.0
        assert config.monitoring.performance_io_threshold_mbps == 100.0
        assert config.monitoring.latency_jitter_threshold_ms == 50.0
        assert config.monitoring.bandwidth_drop_threshold_pct == 50.0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_config.py::TestPerformanceConfig -v`
Expected: FAIL — brak nowych pol w MonitoringConfig

**Step 3: Add MonitorType enums**

```python
# src/guai/core/types.py — dodaj do MonitorType:
    PERFORMANCE = "performance"
    BANDWIDTH = "bandwidth"
    LATENCY = "latency"
```

**Step 4: Add config fields**

```python
# src/guai/core/config.py — dodaj do MonitoringConfig:
    performance_interval: float = Field(default=5.0, gt=0, description="Per-process perf sampling interval (s)")
    bandwidth_interval: float = Field(default=5.0, gt=0, description="Bandwidth sampling interval (s)")
    latency_interval: float = Field(default=10.0, gt=0, description="Latency probe interval (s)")
    latency_targets: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1"],
        description="Hosts to ping for latency measurement",
    )
    performance_cpu_threshold: float = Field(default=80.0, ge=0, le=100, description="CPU alert threshold (%)")
    performance_io_threshold_mbps: float = Field(default=100.0, gt=0, description="IO alert threshold (MB/s)")
    latency_jitter_threshold_ms: float = Field(default=50.0, gt=0, description="Jitter alert threshold (ms)")
    bandwidth_drop_threshold_pct: float = Field(default=50.0, gt=0, le=100, description="Bandwidth drop alert threshold (%)")
```

**Step 5: Run test to verify it passes**

Run: `pytest tests/unit/test_config.py::TestPerformanceConfig -v`
Expected: PASS

**Step 6: Commit**

```bash
git add src/guai/core/types.py src/guai/core/config.py tests/unit/test_config.py
git commit -m "feat: add performance monitor types and config fields"
```

---

## Task 2: PerformanceMonitor — per-process CPU/RAM/IO trendy

**Files:**
- Create: `src/guai/monitors/performance.py`
- Test: `tests/unit/test_performance_monitor.py`

**Step 1: Write failing test**

```python
# tests/unit/test_performance_monitor.py
"""Tests for PerformanceMonitor."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.performance import PerformanceMonitor


def _make_config(interval: float = 0.1, cpu_threshold: float = 80.0) -> MagicMock:
    config = MagicMock()
    config.monitoring.performance_interval = interval
    config.monitoring.performance_cpu_threshold = cpu_threshold
    config.monitoring.performance_io_threshold_mbps = 100.0
    return config


def _make_proc(
    pid: int = 100,
    name: str = "chrome.exe",
    cpu_percent: float = 5.0,
    rss: int = 100_000_000,
    read_bytes: int = 1_000_000,
    write_bytes: int = 500_000,
) -> MagicMock:
    proc = MagicMock()
    proc.pid = pid
    proc.info = {
        "pid": pid,
        "name": name,
        "cpu_percent": cpu_percent,
        "memory_info": MagicMock(rss=rss),
        "io_counters": MagicMock(read_bytes=read_bytes, write_bytes=write_bytes),
    }
    return proc


class TestEmitsProcessSnapshots:
    @pytest.mark.asyncio
    async def test_emits_events_for_active_processes(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = PerformanceMonitor(bus, config)
        monitor._running = True

        proc1 = _make_proc(pid=100, name="chrome.exe", cpu_percent=15.0)
        proc2 = _make_proc(pid=200, name="node.exe", cpu_percent=3.0)

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: list[str]) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc1, proc2]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter

            async for event in monitor.stream():
                events.append(event)

        # Emituje eventy dla procesow z CPU > 0
        assert len(events) >= 1
        assert all(e.source == "performance_monitor" for e in events)
        assert all(e.category == "performance" for e in events)


class TestHighCpuSeverity:
    @pytest.mark.asyncio
    async def test_high_cpu_gets_medium_severity(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config(cpu_threshold=10.0)
        monitor = PerformanceMonitor(bus, config)
        monitor._running = True

        proc = _make_proc(pid=100, name="heavy.exe", cpu_percent=50.0)

        events: list[SecurityEvent] = []

        with patch("guai.monitors.performance.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: list[str]) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter

            async for event in monitor.stream():
                events.append(event)

        high_cpu_events = [e for e in events if e.data.get("cpu_percent", 0) >= 10.0]
        assert len(high_cpu_events) >= 1
        assert high_cpu_events[0].severity == Severity.MEDIUM


class TestMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = PerformanceMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.PERFORMANCE


class TestDataFields:
    @pytest.mark.asyncio
    async def test_event_data_contains_required_fields(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = PerformanceMonitor(bus, config)
        monitor._running = True

        proc = _make_proc(pid=42, name="test.exe", cpu_percent=10.0, rss=200_000_000)

        with patch("guai.monitors.performance.psutil") as mock_psutil:
            call_count = 0

            def fake_process_iter(attrs: list[str]) -> list[MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [proc]
                monitor._running = False
                return []

            mock_psutil.process_iter = fake_process_iter

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) >= 1
        data = events[0].data
        assert "pid" in data
        assert "name" in data
        assert "cpu_percent" in data
        assert "ram_mb" in data
        assert "io_read_bytes" in data
        assert "io_write_bytes" in data
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_performance_monitor.py -v`
Expected: FAIL — ModuleNotFoundError

**Step 3: Implement PerformanceMonitor**

```python
# src/guai/monitors/performance.py
"""Per-process performance monitor for GuAI."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

import psutil

from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)

# Minimum CPU% to report — skip idle processes
_MIN_CPU_PERCENT = 1.0


class PerformanceMonitor(BaseMonitor):
    """Monitors per-process CPU, RAM, and IO usage.

    Emits SecurityEvents with performance data for every process
    above the minimum CPU threshold. Severity escalates when a
    process exceeds the configured cpu_threshold.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        monitoring = getattr(config, "monitoring", None)
        self._interval: float = getattr(monitoring, "performance_interval", 5.0)
        self._cpu_threshold: float = getattr(monitoring, "performance_cpu_threshold", 80.0)
        self._io_threshold_mbps: float = getattr(monitoring, "performance_io_threshold_mbps", 100.0)
        self._prev_io: dict[int, tuple[int, int]] = {}

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.PERFORMANCE

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        while self._running:
            try:
                procs = await asyncio.to_thread(
                    psutil.process_iter,
                    ["pid", "name", "cpu_percent", "memory_info", "io_counters"],
                )
            except Exception:
                logger.exception("Error reading process list")
                await asyncio.sleep(self._interval)
                continue

            for proc in procs:
                try:
                    info = proc.info
                    cpu = info.get("cpu_percent") or 0.0
                    if cpu < _MIN_CPU_PERCENT:
                        continue

                    pid = info["pid"]
                    name = info.get("name", "unknown")
                    mem_info = info.get("memory_info")
                    io_info = info.get("io_counters")

                    ram_mb = round(mem_info.rss / (1024 * 1024), 1) if mem_info else 0.0
                    read_bytes = io_info.read_bytes if io_info else 0
                    write_bytes = io_info.write_bytes if io_info else 0

                    # Delta IO since last sample
                    prev = self._prev_io.get(pid, (0, 0))
                    delta_read = max(0, read_bytes - prev[0])
                    delta_write = max(0, write_bytes - prev[1])
                    self._prev_io[pid] = (read_bytes, write_bytes)

                    # Severity based on CPU
                    if cpu >= self._cpu_threshold:
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.LOW

                    # Check IO spike (delta > threshold MB/s)
                    delta_mb = (delta_read + delta_write) / (1024 * 1024)
                    io_mbps = delta_mb / self._interval if self._interval > 0 else 0
                    if io_mbps >= self._io_threshold_mbps:
                        severity = max(severity, Severity.MEDIUM)

                    yield SecurityEvent.create(
                        source="performance_monitor",
                        severity=severity,
                        category="performance",
                        data={
                            "pid": pid,
                            "name": name,
                            "cpu_percent": round(cpu, 1),
                            "ram_mb": ram_mb,
                            "io_read_bytes": read_bytes,
                            "io_write_bytes": write_bytes,
                            "io_delta_read": delta_read,
                            "io_delta_write": delta_write,
                        },
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    logger.debug("Error reading process info", exc_info=True)
                    continue

            # Clean up stale PIDs from _prev_io
            active_pids = {p.info["pid"] for p in procs if hasattr(p, "info")}
            self._prev_io = {k: v for k, v in self._prev_io.items() if k in active_pids}

            await asyncio.sleep(self._interval)
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_performance_monitor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/guai/monitors/performance.py tests/unit/test_performance_monitor.py
git commit -m "feat: add PerformanceMonitor — per-process CPU/RAM/IO tracking"
```

---

## Task 3: BandwidthMonitor — throughput per interface

**Files:**
- Create: `src/guai/monitors/bandwidth.py`
- Test: `tests/unit/test_bandwidth_monitor.py`

**Step 1: Write failing test**

```python
# tests/unit/test_bandwidth_monitor.py
"""Tests for BandwidthMonitor."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.bandwidth import BandwidthMonitor


def _make_config(interval: float = 0.1, drop_threshold: float = 50.0) -> MagicMock:
    config = MagicMock()
    config.monitoring.bandwidth_interval = interval
    config.monitoring.bandwidth_drop_threshold_pct = drop_threshold
    return config


def _make_counters(bytes_sent: int = 1000, bytes_recv: int = 2000) -> MagicMock:
    c = MagicMock()
    c.bytes_sent = bytes_sent
    c.bytes_recv = bytes_recv
    c.packets_sent = 10
    c.packets_recv = 20
    c.errin = 0
    c.errout = 0
    c.dropin = 0
    c.dropout = 0
    return c


class TestEmitsBandwidthEvents:
    @pytest.mark.asyncio
    async def test_emits_events_per_interface(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = BandwidthMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        with patch("guai.monitors.bandwidth.psutil") as mock_psutil:
            call_count = 0

            def fake_net_io(pernic: bool = False) -> dict[str, MagicMock]:
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    return {
                        "Ethernet": _make_counters(
                            bytes_sent=1000 * call_count,
                            bytes_recv=2000 * call_count,
                        ),
                    }
                monitor._running = False
                return {}

            mock_psutil.net_io_counters = fake_net_io

            async for event in monitor.stream():
                events.append(event)

        # Need at least 2 snapshots for delta, so events from 2nd snapshot
        assert len(events) >= 1
        assert events[0].source == "bandwidth_monitor"
        assert events[0].category == "bandwidth"
        assert "interface" in events[0].data
        assert "throughput_in_kbps" in events[0].data
        assert "throughput_out_kbps" in events[0].data


class TestMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = BandwidthMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.BANDWIDTH
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_bandwidth_monitor.py -v`
Expected: FAIL

**Step 3: Implement BandwidthMonitor**

```python
# src/guai/monitors/bandwidth.py
"""Network bandwidth monitor for GuAI."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

import psutil

from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)


class BandwidthMonitor(BaseMonitor):
    """Monitors network bandwidth per interface.

    Measures throughput (bytes/sec in and out), packet errors, and drops.
    Emits MEDIUM severity when throughput drops significantly compared
    to the rolling average.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        monitoring = getattr(config, "monitoring", None)
        self._interval: float = getattr(monitoring, "bandwidth_interval", 5.0)
        self._drop_threshold_pct: float = getattr(
            monitoring, "bandwidth_drop_threshold_pct", 50.0
        )
        self._prev_counters: dict[str, tuple[int, int]] = {}
        self._avg_throughput: dict[str, tuple[float, float]] = {}  # EMA in/out

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.BANDWIDTH

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        while self._running:
            try:
                counters = await asyncio.to_thread(psutil.net_io_counters, pernic=True)
            except Exception:
                logger.exception("Error reading net IO counters")
                await asyncio.sleep(self._interval)
                continue

            for iface, stats in counters.items():
                # Skip loopback
                if iface.lower().startswith("lo") or "loopback" in iface.lower():
                    continue

                prev = self._prev_counters.get(iface)
                self._prev_counters[iface] = (stats.bytes_recv, stats.bytes_sent)

                if prev is None:
                    continue  # Need baseline

                delta_in = max(0, stats.bytes_recv - prev[0])
                delta_out = max(0, stats.bytes_sent - prev[1])

                throughput_in = delta_in / self._interval if self._interval > 0 else 0
                throughput_out = delta_out / self._interval if self._interval > 0 else 0

                # EMA (alpha=0.3) for rolling average
                avg = self._avg_throughput.get(iface, (throughput_in, throughput_out))
                alpha = 0.3
                new_avg_in = alpha * throughput_in + (1 - alpha) * avg[0]
                new_avg_out = alpha * throughput_out + (1 - alpha) * avg[1]
                self._avg_throughput[iface] = (new_avg_in, new_avg_out)

                # Detect throughput drop
                severity = Severity.LOW
                if avg[0] > 1024 and throughput_in < avg[0] * (1 - self._drop_threshold_pct / 100):
                    severity = Severity.MEDIUM
                if avg[1] > 1024 and throughput_out < avg[1] * (1 - self._drop_threshold_pct / 100):
                    severity = max(severity, Severity.MEDIUM)

                yield SecurityEvent.create(
                    source="bandwidth_monitor",
                    severity=severity,
                    category="bandwidth",
                    data={
                        "interface": iface,
                        "throughput_in_kbps": round(throughput_in / 1024, 1),
                        "throughput_out_kbps": round(throughput_out / 1024, 1),
                        "avg_in_kbps": round(new_avg_in / 1024, 1),
                        "avg_out_kbps": round(new_avg_out / 1024, 1),
                        "errors_in": stats.errin,
                        "errors_out": stats.errout,
                        "drops_in": stats.dropin,
                        "drops_out": stats.dropout,
                    },
                )

            await asyncio.sleep(self._interval)
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_bandwidth_monitor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/guai/monitors/bandwidth.py tests/unit/test_bandwidth_monitor.py
git commit -m "feat: add BandwidthMonitor — throughput per interface with drop detection"
```

---

## Task 4: LatencyMonitor — ping/jitter do endpointow

**Files:**
- Create: `src/guai/monitors/latency.py`
- Test: `tests/unit/test_latency_monitor.py`

**Step 1: Write failing test**

```python
# tests/unit/test_latency_monitor.py
"""Tests for LatencyMonitor."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.latency import LatencyMonitor


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


class TestEmitsLatencyEvents:
    @pytest.mark.asyncio
    async def test_emits_latency_for_each_target(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config(targets=["8.8.8.8", "1.1.1.1"])
        monitor = LatencyMonitor(bus, config)
        monitor._running = True

        events: list[SecurityEvent] = []

        # Mock ping to return deterministic results
        ping_output = (
            "Pinging 8.8.8.8 with 32 bytes of data:\n"
            "Reply from 8.8.8.8: bytes=32 time=25ms TTL=115\n"
            "Reply from 8.8.8.8: bytes=32 time=30ms TTL=115\n"
            "Reply from 8.8.8.8: bytes=32 time=28ms TTL=115\n"
            "\n"
            "Ping statistics for 8.8.8.8:\n"
            "    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 25ms, Maximum = 30ms, Average = 27ms\n"
        )

        with patch("guai.monitors.latency.LatencyMonitor._ping") as mock_ping:
            call_count = 0

            async def fake_ping(target: str) -> dict[str, float | None]:
                nonlocal call_count
                call_count += 1
                if call_count > 2:
                    monitor._running = False
                return {"avg_ms": 27.0, "min_ms": 25.0, "max_ms": 30.0, "loss_pct": 0.0, "jitter_ms": 5.0}

            mock_ping.side_effect = fake_ping

            async for event in monitor.stream():
                events.append(event)

        assert len(events) >= 2
        assert all(e.source == "latency_monitor" for e in events)
        assert all(e.category == "latency" for e in events)
        assert "target" in events[0].data
        assert "avg_ms" in events[0].data
        assert "jitter_ms" in events[0].data
        assert "loss_pct" in events[0].data


class TestHighJitterSeverity:
    @pytest.mark.asyncio
    async def test_high_jitter_medium_severity(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config(targets=["8.8.8.8"], jitter_threshold=10.0)
        monitor = LatencyMonitor(bus, config)
        monitor._running = True

        with patch("guai.monitors.latency.LatencyMonitor._ping") as mock_ping:
            call_count = 0

            async def fake_ping(target: str) -> dict[str, float | None]:
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    monitor._running = False
                return {"avg_ms": 100.0, "min_ms": 20.0, "max_ms": 200.0, "loss_pct": 0.0, "jitter_ms": 180.0}

            mock_ping.side_effect = fake_ping

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) >= 1
        assert events[0].severity == Severity.MEDIUM


class TestPacketLossSeverity:
    @pytest.mark.asyncio
    async def test_packet_loss_high_severity(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config(targets=["8.8.8.8"])
        monitor = LatencyMonitor(bus, config)
        monitor._running = True

        with patch("guai.monitors.latency.LatencyMonitor._ping") as mock_ping:
            call_count = 0

            async def fake_ping(target: str) -> dict[str, float | None]:
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    monitor._running = False
                return {"avg_ms": None, "min_ms": None, "max_ms": None, "loss_pct": 100.0, "jitter_ms": 0.0}

            mock_ping.side_effect = fake_ping

            events: list[SecurityEvent] = []
            async for event in monitor.stream():
                events.append(event)

        assert len(events) >= 1
        assert events[0].severity == Severity.HIGH


class TestMonitorType:
    def test_monitor_type(self) -> None:
        bus = EventBus(max_queue_size=100)
        config = _make_config()
        monitor = LatencyMonitor(bus, config)
        assert monitor.monitor_type == MonitorType.LATENCY
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_latency_monitor.py -v`
Expected: FAIL

**Step 3: Implement LatencyMonitor**

```python
# src/guai/monitors/latency.py
"""Latency and jitter monitor for GuAI."""
from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)

_TIME_RE = re.compile(r"time[=<](\d+(?:\.\d+)?)ms", re.IGNORECASE)
_LOSS_RE = re.compile(r"\((\d+)% loss\)", re.IGNORECASE)


class LatencyMonitor(BaseMonitor):
    """Measures latency and jitter to configurable targets via ping.

    Emits events with avg/min/max latency, jitter (max-min), and packet loss.
    Severity:
        - LOW: normal latency
        - MEDIUM: jitter exceeds threshold
        - HIGH: packet loss > 0%
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        monitoring = getattr(config, "monitoring", None)
        self._interval: float = getattr(monitoring, "latency_interval", 10.0)
        self._targets: list[str] = getattr(monitoring, "latency_targets", ["8.8.8.8"])
        self._jitter_threshold: float = getattr(
            monitoring, "latency_jitter_threshold_ms", 50.0
        )

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.LATENCY

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        while self._running:
            for target in self._targets:
                if not self._running:
                    break
                try:
                    result = await self._ping(target)
                except Exception:
                    logger.debug("Ping to %s failed", target, exc_info=True)
                    result = {
                        "avg_ms": None,
                        "min_ms": None,
                        "max_ms": None,
                        "loss_pct": 100.0,
                        "jitter_ms": 0.0,
                    }

                loss = result.get("loss_pct") or 0.0
                jitter = result.get("jitter_ms") or 0.0

                if loss > 0:
                    severity = Severity.HIGH
                elif jitter >= self._jitter_threshold:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                yield SecurityEvent.create(
                    source="latency_monitor",
                    severity=severity,
                    category="latency",
                    data={
                        "target": target,
                        "avg_ms": result.get("avg_ms"),
                        "min_ms": result.get("min_ms"),
                        "max_ms": result.get("max_ms"),
                        "loss_pct": loss,
                        "jitter_ms": jitter,
                    },
                )

            await asyncio.sleep(self._interval)

    async def _ping(self, target: str, count: int = 3) -> dict[str, float | None]:
        """Run ping and parse results.

        Returns dict with avg_ms, min_ms, max_ms, loss_pct, jitter_ms.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", str(count), "-w", "2000", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            output = stdout.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            return {"avg_ms": None, "min_ms": None, "max_ms": None, "loss_pct": 100.0, "jitter_ms": 0.0}

        # Parse individual times
        times = [float(m.group(1)) for m in _TIME_RE.finditer(output)]

        # Parse loss
        loss_match = _LOSS_RE.search(output)
        loss_pct = float(loss_match.group(1)) if loss_match else (100.0 if not times else 0.0)

        if not times:
            return {"avg_ms": None, "min_ms": None, "max_ms": None, "loss_pct": loss_pct, "jitter_ms": 0.0}

        avg_ms = round(sum(times) / len(times), 1)
        min_ms = round(min(times), 1)
        max_ms = round(max(times), 1)
        jitter_ms = round(max_ms - min_ms, 1)

        return {
            "avg_ms": avg_ms,
            "min_ms": min_ms,
            "max_ms": max_ms,
            "loss_pct": loss_pct,
            "jitter_ms": jitter_ms,
        }
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_latency_monitor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/guai/monitors/latency.py tests/unit/test_latency_monitor.py
git commit -m "feat: add LatencyMonitor — ping/jitter/packet loss measurement"
```

---

## Task 5: Rejestracja monitorow w app.py i __init__.py

**Files:**
- Modify: `src/guai/core/app.py`
- Modify: `src/guai/monitors/__init__.py`
- Modify: `config/guai.toml`
- Modify: `config/guai.example.toml`

**Step 1: Update monitors/__init__.py**

```python
# Dodaj importy:
from guai.monitors.bandwidth import BandwidthMonitor
from guai.monitors.latency import LatencyMonitor
from guai.monitors.performance import PerformanceMonitor

# Dodaj do __all__:
    "BandwidthMonitor",
    "LatencyMonitor",
    "PerformanceMonitor",
```

**Step 2: Register in app.py initialize()**

Dodaj po bloku `if "dns" in enabled:`:

```python
        if "performance" in enabled:
            from guai.monitors.performance import PerformanceMonitor
            self.monitors.append(PerformanceMonitor(self.event_bus, self.config))
        if "bandwidth" in enabled:
            from guai.monitors.bandwidth import BandwidthMonitor
            self.monitors.append(BandwidthMonitor(self.event_bus, self.config))
        if "latency" in enabled:
            from guai.monitors.latency import LatencyMonitor
            self.monitors.append(LatencyMonitor(self.event_bus, self.config))
```

**Step 3: Update config/guai.toml**

Dodaj do `[monitoring]`:
```toml
performance_interval = 5.0
bandwidth_interval = 5.0
latency_interval = 10.0
latency_targets = ["8.8.8.8", "1.1.1.1"]
performance_cpu_threshold = 80.0
performance_io_threshold_mbps = 100.0
latency_jitter_threshold_ms = 50.0
bandwidth_drop_threshold_pct = 50.0
```

Dodaj `"performance"`, `"bandwidth"`, `"latency"` do `enabled_monitors`.

**Step 4: Update config/guai.example.toml analogicznie**

**Step 5: Run all tests**

Run: `pytest tests/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add src/guai/core/app.py src/guai/monitors/__init__.py config/guai.toml config/guai.example.toml
git commit -m "feat: register performance/bandwidth/latency monitors in app"
```

---

## Task 6: Reguly detekcyjne dla performance

**Files:**
- Create: `config/rules/high_cpu.yaml`
- Create: `config/rules/bandwidth_drop.yaml`
- Create: `config/rules/high_jitter.yaml`
- Create: `config/rules/packet_loss.yaml`

**Step 1: Create rules**

```yaml
# config/rules/high_cpu.yaml
name: high_cpu_process
description: Process consuming excessive CPU for sustained period
severity: 2
source: performance
conditions:
  category: performance
  data.cpu_percent:
    gte: 80
window_seconds: 30
threshold: 3
mitre_technique: null
enabled: true
```

```yaml
# config/rules/bandwidth_drop.yaml
name: bandwidth_drop
description: Significant network throughput drop detected on interface
severity: 2
source: bandwidth
conditions:
  category: bandwidth
  severity:
    gte: 2
window_seconds: 30
threshold: 3
mitre_technique: null
enabled: true
```

```yaml
# config/rules/high_jitter.yaml
name: high_jitter
description: Network jitter exceeds acceptable threshold
severity: 2
source: latency
conditions:
  category: latency
  data.jitter_ms:
    gte: 50
window_seconds: 60
threshold: 3
mitre_technique: null
enabled: true
```

```yaml
# config/rules/packet_loss.yaml
name: packet_loss
description: Packet loss detected to monitoring targets
severity: 3
source: latency
conditions:
  category: latency
  data.loss_pct:
    gt: 0
window_seconds: 0
threshold: 1
mitre_technique: null
enabled: true
```

**Step 2: Verify rules load**

Run: `python -c "from guai.rules.models import DetectionRule; r = DetectionRule.from_yaml('config/rules/high_cpu.yaml'); print(r.name, r.severity)"`
Expected: `high_cpu_process 2`

**Step 3: Commit**

```bash
git add config/rules/high_cpu.yaml config/rules/bandwidth_drop.yaml config/rules/high_jitter.yaml config/rules/packet_loss.yaml
git commit -m "feat: add detection rules for performance anomalies"
```

---

## Task 7: MCP tools dla performance data

**Files:**
- Modify: `src/guai/mcp/server.py`

**Step 1: Add guai_perf_top tool**

Dodaj nowy tool do server.py:

```python
@mcp.tool()
async def guai_perf_top(limit: int = 10) -> str:
    """Top processes by CPU usage from latest performance snapshot."""
    events = await event_store.query(category="performance", limit=200, since=_since("5m"))
    if not events:
        return json.dumps({"processes": [], "message": "No performance data yet"})

    # Deduplicate by PID — keep latest
    by_pid: dict[int, dict] = {}
    for e in events:
        data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
        pid = data.get("pid")
        if pid is not None:
            by_pid[pid] = data

    # Sort by CPU descending
    top = sorted(by_pid.values(), key=lambda d: d.get("cpu_percent", 0), reverse=True)[:limit]
    return json.dumps({"processes": top, "count": len(top)}, indent=2)


@mcp.tool()
async def guai_bandwidth(since: str = "5m") -> str:
    """Current bandwidth stats per interface."""
    events = await event_store.query(category="bandwidth", limit=50, since=_since(since))
    if not events:
        return json.dumps({"interfaces": [], "message": "No bandwidth data yet"})

    by_iface: dict[str, dict] = {}
    for e in events:
        data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
        iface = data.get("interface")
        if iface:
            by_iface[iface] = data

    return json.dumps({"interfaces": list(by_iface.values())}, indent=2)


@mcp.tool()
async def guai_latency(since: str = "5m") -> str:
    """Latest latency measurements per target."""
    events = await event_store.query(category="latency", limit=50, since=_since(since))
    if not events:
        return json.dumps({"targets": [], "message": "No latency data yet"})

    by_target: dict[str, dict] = {}
    for e in events:
        data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
        target = data.get("target")
        if target:
            by_target[target] = data

    return json.dumps({"targets": list(by_target.values())}, indent=2)
```

Uwaga: `_since()` to helper konwertujacy string "5m"/"1h" na datetime — uzyj istniejacego `parse_since` z `guai.mcp.tools`.

**Step 2: Run integration test**

Run: `pytest tests/ -v`
Expected: PASS

**Step 3: Commit**

```bash
git add src/guai/mcp/server.py
git commit -m "feat: add MCP tools for performance/bandwidth/latency queries"
```

---

## Task 8: Update dokumentacji

**Files:**
- Modify: `README.md`

**Step 1: Dodaj nowe monitory do tabeli w README**

Dodaj do tabeli monitorow:
- PerformanceMonitor | psutil process_iter() | Per-process CPU/RAM/IO trendy, spikes
- BandwidthMonitor | psutil net_io_counters() | Throughput per interface, drop detection
- LatencyMonitor | ping (subprocess) | Latency/jitter/packet loss do targets

Dodaj nowe reguly do tabeli regul.
Dodaj nowe MCP tools do tabeli.

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with performance monitors"
```

---

## Podsumowanie

Po wykonaniu wszystkich taskow GuAI bedzie mial:
- **PerformanceMonitor** — per-process CPU/RAM/IO z delta tracking
- **BandwidthMonitor** — throughput per interface z EMA i drop detection
- **LatencyMonitor** — ping/jitter/packet loss do konfigurowalnych targetow
- **4 nowe reguly** — high_cpu, bandwidth_drop, high_jitter, packet_loss
- **3 nowe MCP tools** — guai_perf_top, guai_bandwidth, guai_latency
- Wszystko generyczne, zero hardcode na konkretne procesy
