"""Latency and jitter monitor for GuAI."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

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
        """Run ping and parse results."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping",
                "-n",
                str(count),
                "-w",
                "2000",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            output = stdout.decode("utf-8", errors="replace")
        except TimeoutError:
            return {
                "avg_ms": None,
                "min_ms": None,
                "max_ms": None,
                "loss_pct": 100.0,
                "jitter_ms": 0.0,
            }

        # Parse individual reply times
        times = [float(m.group(1)) for m in _TIME_RE.finditer(output)]

        # Parse loss percentage
        loss_match = _LOSS_RE.search(output)
        loss_pct = float(loss_match.group(1)) if loss_match else (100.0 if not times else 0.0)

        if not times:
            return {
                "avg_ms": None,
                "min_ms": None,
                "max_ms": None,
                "loss_pct": loss_pct,
                "jitter_ms": 0.0,
            }

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
