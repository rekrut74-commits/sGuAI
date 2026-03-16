"""Abstract base class for all GuAI security monitors."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType

logger = logging.getLogger(__name__)


class BaseMonitor(ABC):
    """Abstract base class for security monitors.

    Monitors produce a stream of SecurityEvents by observing some aspect
    of the system (network, processes, event log, etc.).  The ``start()``
    method runs the ``stream()`` generator and publishes each event to
    the shared EventBus.

    Subclasses MUST implement:
        - ``stream()`` — async generator yielding SecurityEvents
        - ``monitor_type`` — property returning the MonitorType enum value
    """

    def __init__(self, event_bus: EventBus, config: Any) -> None:
        self.event_bus = event_bus
        self.config = config
        self._running = False
        self._health = ModuleHealth.STOPPED
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start monitoring -- runs stream() and publishes to event_bus."""
        if self._running:
            return
        self._running = True
        self._health = ModuleHealth.HEALTHY
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Monitor %s started", self.monitor_type.value)

    async def stop(self) -> None:
        """Stop monitoring gracefully."""
        if not self._running:
            return
        self._running = False
        self._health = ModuleHealth.STOPPED

        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Monitor %s stopped", self.monitor_type.value)

    @property
    def health(self) -> ModuleHealth:
        """Return current health status of this monitor."""
        return self._health

    @property
    @abstractmethod
    def monitor_type(self) -> MonitorType:
        """Return the type of this monitor."""
        ...

    @abstractmethod
    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield security events.

        MUST use ``asyncio.to_thread()`` for any blocking / synchronous calls
        (e.g. psutil, win32evtlog).
        """
        ...
        # Make this a valid async generator so subclasses can override properly
        if False:  # pragma: no cover
            yield  # type: ignore[misc]

    async def _run_loop(self) -> None:
        """Internal loop: iterate stream() and publish events."""
        try:
            async for event in self.stream():
                if not self._running:
                    break
                await self.event_bus.publish(event)
        except asyncio.CancelledError:
            pass
        except Exception:
            self._health = ModuleHealth.UNHEALTHY
            logger.exception("Monitor %s encountered an error", self.monitor_type.value)
