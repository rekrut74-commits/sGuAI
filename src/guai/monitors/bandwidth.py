"""Network bandwidth monitor for GuAI."""

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
                if (
                    avg[0] > 1024
                    and throughput_in < avg[0] * (1 - self._drop_threshold_pct / 100)
                ):
                    severity = Severity.MEDIUM
                if (
                    avg[1] > 1024
                    and throughput_out < avg[1] * (1 - self._drop_threshold_pct / 100)
                ):
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
