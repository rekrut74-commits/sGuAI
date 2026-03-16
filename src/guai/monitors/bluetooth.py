"""Bluetooth Low Energy (BLE) monitor for GuAI.

Uses the ``bleak`` library for async BLE scanning.
Falls back gracefully when bleak is not installed or no adapter is present.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)


class BluetoothMonitor(BaseMonitor):
    """Monitors nearby Bluetooth Low Energy devices.

    Uses ``bleak.BleakScanner`` when available. On systems without
    bleak or without a Bluetooth adapter the monitor sets health to
    DEGRADED and yields nothing.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "bluetooth_interval", 15.0
        )
        self._known_devices: set[str] = set()
        self._bleak: Any = None
        self._available = False
        try:
            import bleak  # type: ignore[import-untyped]

            self._bleak = bleak
            self._available = True
        except ImportError:
            logger.info("bleak not available -- BluetoothMonitor will be inactive")

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.BLUETOOTH

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield events for BLE device changes."""
        if not self._available or self._bleak is None:
            self._health = ModuleHealth.DEGRADED
            logger.warning("BluetoothMonitor inactive: bleak not available")
            return

        # Probe adapter
        try:
            await self._bleak.BleakScanner.discover(timeout=2.0, return_adv=True)
        except Exception:
            self._health = ModuleHealth.DEGRADED
            logger.warning("BluetoothMonitor inactive: no Bluetooth adapter found")
            return

        while self._running:
            try:
                # return_adv=True gives dict[str, (BLEDevice, AdvertisementData)]
                # AdvertisementData has .rssi (BLEDevice does not in bleak 2.x)
                results = await self._bleak.BleakScanner.discover(
                    timeout=5.0, return_adv=True
                )
                current_addresses: set[str] = set()

                for _addr, (dev, adv) in results.items():
                    addr = dev.address.lower()
                    current_addresses.add(addr)

                    if addr not in self._known_devices:
                        rssi = getattr(adv, "rssi", None)
                        yield SecurityEvent.create(
                            source="bluetooth_monitor",
                            severity=Severity.LOW,
                            category="bluetooth",
                            data={
                                "event_type": "new_device",
                                "name": dev.name or "unknown",
                                "address": addr,
                                "rssi": rssi,
                            },
                        )

                # Disappeared devices
                disappeared = self._known_devices - current_addresses
                for addr in disappeared:
                    yield SecurityEvent.create(
                        source="bluetooth_monitor",
                        severity=Severity.LOW,
                        category="bluetooth",
                        data={
                            "event_type": "device_disappeared",
                            "address": addr,
                        },
                    )

                self._known_devices = current_addresses

            except Exception:
                logger.exception("Error scanning Bluetooth devices")

            await asyncio.sleep(self._interval)
