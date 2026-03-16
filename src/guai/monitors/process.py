"""Process monitor for GuAI."""

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

# Parent processes whose child spawns are suspicious.
# Key = parent process name, Value = list of suspicious child process names.
SUSPICIOUS_PARENTS: dict[str, list[str]] = {
    "WINWORD.EXE": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "EXCEL.EXE": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "OUTLOOK.EXE": ["cmd.exe", "powershell.exe"],
    "svchost.exe": ["cmd.exe", "powershell.exe"],
}


class ProcessMonitor(BaseMonitor):
    """Monitors running processes using psutil.

    Detects new processes and flags suspicious parent-child relationships
    commonly used in malware/exploit chains.
    """

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._known_pids: set[int] = set()
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "process_interval", 5.0
        )

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.PROCESS

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield events for new processes detected."""
        while self._running:
            try:
                processes = await asyncio.to_thread(
                    lambda: list(
                        psutil.process_iter(["pid", "name", "cmdline", "ppid"])
                    )
                )
            except Exception:
                logger.exception("Error iterating processes")
                await asyncio.sleep(self._interval)
                continue

            current_pids: set[int] = set()
            for proc in processes:
                try:
                    info = proc.info  # type: ignore[attr-defined]
                    pid: int = info["pid"]
                    current_pids.add(pid)

                    if pid in self._known_pids:
                        continue

                    name: str = info.get("name") or "unknown"
                    cmdline: list[str] = info.get("cmdline") or []
                    ppid: int | None = info.get("ppid")

                    parent_name = self._get_parent_name(ppid, processes)
                    severity = self._assess_severity(name, parent_name)

                    event = SecurityEvent.create(
                        source="process_monitor",
                        severity=severity,
                        category="process",
                        data={
                            "pid": pid,
                            "name": name,
                            "cmdline": cmdline,
                            "ppid": ppid,
                            "parent_name": parent_name,
                        },
                    )
                    yield event

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            self._known_pids = current_pids
            await asyncio.sleep(self._interval)

    @staticmethod
    def _get_parent_name(ppid: int | None, processes: list[Any]) -> str:
        """Look up the parent process name from the process list."""
        if ppid is None:
            return "unknown"
        for proc in processes:
            try:
                info = proc.info  # type: ignore[attr-defined]
                if info["pid"] == ppid:
                    return info.get("name") or "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        return "unknown"

    @staticmethod
    def _assess_severity(child_name: str, parent_name: str) -> Severity:
        """Assess severity based on suspicious parent-child relationships."""
        for parent_pattern, suspicious_children in SUSPICIOUS_PARENTS.items():
            if parent_name.upper() == parent_pattern.upper():
                if child_name.lower() in [c.lower() for c in suspicious_children]:
                    return Severity.HIGH
        return Severity.LOW
