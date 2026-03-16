"""Network connection monitor for GuAI."""

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


class NetworkMonitor(BaseMonitor):
    """Monitors TCP/UDP connections using psutil.

    Detects new connections that were not present in the previous snapshot
    and emits SecurityEvents for each one.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._known_connections: set[tuple[str, ...]] = set()
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "network_interval", 5.0
        )

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.NETWORK

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield events for new connections detected since last snapshot."""
        while self._running:
            try:
                connections = await asyncio.to_thread(psutil.net_connections)
            except (psutil.AccessDenied, PermissionError):
                logger.warning("Access denied reading network connections")
                await asyncio.sleep(self._interval)
                continue
            except Exception:
                logger.exception("Error reading network connections")
                await asyncio.sleep(self._interval)
                continue

            current_keys: set[tuple[str, ...]] = set()
            for conn in connections:
                key = self._connection_key(conn)
                current_keys.add(key)

                if key not in self._known_connections:
                    local_addr = (
                        f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                    )
                    remote_addr = (
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "none"
                    )
                    event = SecurityEvent.create(
                        source="network_monitor",
                        severity=Severity.LOW,
                        category="network",
                        data={
                            "local_addr": local_addr,
                            "remote_addr": remote_addr,
                            "status": conn.status if hasattr(conn, "status") else "unknown",
                            "pid": conn.pid,
                        },
                    )
                    yield event

            self._known_connections = current_keys
            await asyncio.sleep(self._interval)

    @staticmethod
    def _connection_key(conn: Any) -> tuple[str, ...]:
        """Create a hashable key for a connection."""
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        status = conn.status if hasattr(conn, "status") else ""
        pid = str(conn.pid) if conn.pid else ""
        return (local, remote, status, pid)
