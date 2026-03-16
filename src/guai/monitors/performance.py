"""Per-process performance monitor for GuAI."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

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
        self._io_threshold_mbps: float = getattr(
            monitoring, "performance_io_threshold_mbps", 100.0
        )
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

            active_pids: set[int] = set()

            for proc in procs:
                try:
                    info = proc.info
                    cpu = info.get("cpu_percent") or 0.0
                    if cpu < _MIN_CPU_PERCENT:
                        continue

                    pid = info["pid"]
                    active_pids.add(pid)
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
                    severity = Severity.MEDIUM if cpu >= self._cpu_threshold else Severity.LOW

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

            # Clean up stale PIDs
            self._prev_io = {k: v for k, v in self._prev_io.items() if k in active_pids}

            await asyncio.sleep(self._interval)
