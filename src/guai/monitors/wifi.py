"""WiFi network monitor for GuAI.

Scans nearby WiFi networks using ``netsh wlan show networks`` on Windows.
Falls back to ``netsh wlan show interfaces`` when Location Services are
disabled (Windows 11 requirement). Falls back gracefully when no WiFi
adapter is present.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from collections.abc import AsyncIterator
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)


class WiFiMonitor(BaseMonitor):
    """Monitors nearby WiFi networks for security-relevant changes.

    Uses ``netsh wlan show networks mode=bssid`` to discover networks.
    Falls back to ``netsh wlan show interfaces`` (connected network only)
    when Location Services are not enabled on Windows 11.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "wifi_interval", 10.0
        )
        self._known_bssids: set[str] = set()
        self._known_connected: str = ""  # BSSID of last connected network
        self._available = True
        self._scan_mode: str = "full"  # "full" or "interfaces"

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.WIFI

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield events for WiFi network changes."""
        # Check if WiFi adapter exists
        has_adapter = await asyncio.to_thread(self._has_wifi_adapter)
        if not has_adapter:
            self._available = False
            self._health = ModuleHealth.DEGRADED
            logger.warning("WiFiMonitor inactive: no WiFi adapter found")
            return

        # Try full scan mode first
        probe = await asyncio.to_thread(self._run_netsh_networks)
        if probe is not None:
            self._scan_mode = "full"
        else:
            # Fall back to interfaces-only mode
            self._scan_mode = "interfaces"
            self._health = ModuleHealth.DEGRADED
            logger.warning(
                "WiFiMonitor degraded: using 'show interfaces' only. "
                "For full scan, enable Location Services: "
                "Settings > Privacy & Security > Location"
            )

        while self._running:
            try:
                if self._scan_mode == "full":
                    yield_from = self._scan_full()
                else:
                    yield_from = self._scan_interfaces()

                async for event in yield_from:
                    yield event

            except Exception:
                logger.exception("Error scanning WiFi networks")

            await asyncio.sleep(self._interval)

    async def _scan_full(self) -> AsyncIterator[SecurityEvent]:
        """Scan using 'netsh wlan show networks mode=bssid'."""
        output = await asyncio.to_thread(self._run_netsh_networks)
        if output is None:
            return

        networks = self._parse_networks(output)
        current_bssids = {n["bssid"] for n in networks}

        for net in networks:
            if net["bssid"] not in self._known_bssids:
                severity = Severity.LOW
                event_type = "new_network"

                if net["auth"].lower() in ("open", ""):
                    severity = Severity.MEDIUM
                    event_type = "open_network"

                yield SecurityEvent.create(
                    source="wifi_monitor",
                    severity=severity,
                    category="wifi",
                    data={
                        "event_type": event_type,
                        "ssid": net["ssid"],
                        "bssid": net["bssid"],
                        "signal": net["signal"],
                        "channel": net["channel"],
                        "auth": net["auth"],
                    },
                )

        disappeared = self._known_bssids - current_bssids
        for bssid in disappeared:
            yield SecurityEvent.create(
                source="wifi_monitor",
                severity=Severity.LOW,
                category="wifi",
                data={"event_type": "network_disappeared", "bssid": bssid},
            )

        self._known_bssids = current_bssids

    async def _scan_interfaces(self) -> AsyncIterator[SecurityEvent]:
        """Fallback: scan using 'netsh wlan show interfaces' (connected only)."""
        output = await asyncio.to_thread(self._run_netsh_interfaces)
        if output is None:
            return

        info = self._parse_interface(output)
        if info is None:
            # Not connected — emit disconnect if we were connected
            if self._known_connected:
                yield SecurityEvent.create(
                    source="wifi_monitor",
                    severity=Severity.LOW,
                    category="wifi",
                    data={
                        "event_type": "wifi_disconnected",
                        "bssid": self._known_connected,
                    },
                )
                self._known_connected = ""
            return

        bssid = info["bssid"]
        if bssid != self._known_connected:
            severity = Severity.LOW
            event_type = "wifi_connected"

            if info["auth"].lower() in ("open", ""):
                severity = Severity.MEDIUM
                event_type = "open_network"

            yield SecurityEvent.create(
                source="wifi_monitor",
                severity=severity,
                category="wifi",
                data={
                    "event_type": event_type,
                    "ssid": info["ssid"],
                    "bssid": bssid,
                    "signal": info["signal"],
                    "channel": info["channel"],
                    "auth": info["auth"],
                },
            )
            self._known_connected = bssid

    @staticmethod
    def _has_wifi_adapter() -> bool:
        """Check if a WiFi adapter exists via 'netsh wlan show interfaces'."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "Name" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _run_netsh_networks() -> str | None:
        """Run 'netsh wlan show networks mode=bssid'. Returns None on failure."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _run_netsh_interfaces() -> str | None:
        """Run 'netsh wlan show interfaces'. Returns None on failure."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _parse_interface(output: str) -> dict[str, str] | None:
        """Parse 'netsh wlan show interfaces' for connected network info."""
        fields: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            for key, field in [
                ("SSID", "ssid"),
                ("BSSID", "bssid"),
                ("Signal", "signal"),
                ("Channel", "channel"),
                ("Authentication", "auth"),
                ("State", "state"),
            ]:
                m = re.match(rf"^{key}\s*:\s*(.*)", line)
                if m:
                    fields[field] = m.group(1).strip()
                    break

        if fields.get("state", "").lower() != "connected":
            return None
        if not fields.get("bssid"):
            return None

        return {
            "ssid": fields.get("ssid", ""),
            "bssid": fields.get("bssid", "").lower(),
            "signal": fields.get("signal", ""),
            "channel": fields.get("channel", ""),
            "auth": fields.get("auth", ""),
        }

    @staticmethod
    def _parse_networks(output: str) -> list[dict[str, str]]:
        """Parse netsh wlan output into a list of network dicts.

        Authentication is an SSID-level attribute and is carried forward
        to all BSSIDs under the same SSID.
        """
        networks: list[dict[str, str]] = []
        current: dict[str, str] = {}
        ssid_auth = ""  # SSID-level auth carried to all BSSIDs

        for line in output.splitlines():
            line = line.strip()

            # Match "SSID N : value" pattern
            m = re.match(r"^SSID\s+\d+\s*:\s*(.*)", line)
            if m:
                if current.get("bssid"):
                    networks.append(current)
                ssid_auth = ""
                current = {
                    "ssid": m.group(1).strip(),
                    "bssid": "", "signal": "", "channel": "", "auth": "",
                }
                continue

            # Authentication appears at SSID level (before BSSIDs)
            m = re.match(r"^Authentication\s*:\s*(.*)", line)
            if m:
                ssid_auth = m.group(1).strip()
                current["auth"] = ssid_auth
                continue

            # Match "BSSID N : value"
            m = re.match(r"^BSSID\s+\d+\s*:\s*(.*)", line)
            if m:
                if current.get("bssid"):
                    # Multiple BSSIDs for same SSID — save previous
                    networks.append(current)
                    ssid = current["ssid"]
                    current = {
                        "ssid": ssid, "bssid": "", "signal": "",
                        "channel": "", "auth": ssid_auth,
                    }
                current["bssid"] = m.group(1).strip().lower()
                continue

            # Match per-BSSID key-value pairs
            m = re.match(r"^Signal\s*:\s*(.*)", line)
            if m:
                current["signal"] = m.group(1).strip()
                continue

            m = re.match(r"^Channel\s*:\s*(.*)", line)
            if m:
                current["channel"] = m.group(1).strip()
                continue

        # Don't forget the last entry
        if current.get("bssid"):
            networks.append(current)

        return networks
