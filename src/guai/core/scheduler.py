"""Periodic task scheduler for GuAI system."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)


class Scheduler:
    """Manages periodic async tasks.

    Each task runs a coroutine factory at a fixed interval.
    Tasks are started/stopped together or can be individually cancelled.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._specs: dict[str, tuple[Callable[[], Coroutine[Any, Any, None]], float]] = {}
        self._running = False

    def schedule(
        self,
        name: str,
        coro_factory: Callable[[], Coroutine[Any, Any, None]],
        interval: float,
    ) -> None:
        """Register a periodic task (started on ``start()``).

        Args:
            name: Unique name for the task.
            coro_factory: Zero-arg callable returning an awaitable to run each tick.
            interval: Seconds between invocations.
        """
        self._specs[name] = (coro_factory, interval)

    async def start(self) -> None:
        """Start all registered periodic tasks."""
        if self._running:
            return
        self._running = True
        for name, (factory, interval) in self._specs.items():
            self._tasks[name] = asyncio.create_task(
                self._loop(name, factory, interval),
            )
        logger.info("Scheduler started with %d tasks", len(self._tasks))

    async def stop(self) -> None:
        """Cancel all running tasks and wait for them to finish."""
        if not self._running:
            return
        self._running = False

        for task in self._tasks.values():
            task.cancel()

        results = await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        for name, result in zip(self._tasks.keys(), results):
            if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                logger.error("Scheduler task %s exited with error: %s", name, result)

        self._tasks.clear()
        logger.info("Scheduler stopped")

    @property
    def running_tasks(self) -> list[str]:
        """Return names of currently running tasks."""
        return [name for name, task in self._tasks.items() if not task.done()]

    async def _loop(
        self,
        name: str,
        coro_factory: Callable[[], Coroutine[Any, Any, None]],
        interval: float,
    ) -> None:
        """Execute *coro_factory* every *interval* seconds until cancelled."""
        while self._running:
            try:
                await coro_factory()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Error in scheduled task %s", name)

            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
