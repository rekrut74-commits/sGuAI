"""Async EventBus with back-pressure support for GuAI.

Provides publish/subscribe infrastructure for SecurityEvent routing
with configurable queue size and drop strategies.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import Severity

logger = logging.getLogger(__name__)


@dataclass
class EventFilter:
    """Filter criteria for event subscriptions."""

    category: str | None = None
    min_severity: Severity | None = None

    def matches(self, event: SecurityEvent) -> bool:
        """Check if an event matches this filter's criteria.

        Args:
            event: The SecurityEvent to check.

        Returns:
            True if the event matches all specified filter criteria.
        """
        if self.category is not None and event.category != self.category:
            return False
        if self.min_severity is not None and event.severity < self.min_severity:
            return False
        return True


@dataclass
class _Subscription:
    """Internal representation of an event subscription."""

    subscription_id: str
    callback: Callable[[SecurityEvent], Awaitable[None]]
    event_filter: EventFilter


class EventBus:
    """Async event bus with back-pressure for SecurityEvent routing.

    Features:
        - asyncio.Queue-based with configurable max size
        - Non-blocking publish with drop strategy (oldest or newest)
        - Filter-based dispatch to subscribers
        - Stats tracking (dropped, published, queue size)
        - Proper start/stop lifecycle

    Args:
        max_queue_size: Maximum number of events in the queue.
        drop_strategy: What to drop when queue is full — "oldest" or "newest".
    """

    def __init__(
        self,
        max_queue_size: int = 10_000,
        drop_strategy: str = "oldest",
    ) -> None:
        if drop_strategy not in ("oldest", "newest"):
            raise ValueError(f"Invalid drop_strategy: {drop_strategy!r}. Use 'oldest' or 'newest'.")

        self._max_queue_size = max_queue_size
        self._drop_strategy = drop_strategy

        # Use a bounded queue for back-pressure awareness,
        # but we manage overflow manually for drop-oldest strategy.
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=0)
        self._subscribers: dict[str, _Subscription] = {}

        self._dropped_count: int = 0
        self._total_published: int = 0
        self._running: bool = False
        self._dispatch_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the dispatch loop.

        Events published before start() are queued and will be dispatched
        once the loop begins.
        """
        if self._running:
            return
        self._running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())

    async def stop(self) -> None:
        """Stop the dispatch loop and drain remaining events.

        Processes all queued events before shutting down.
        """
        if not self._running:
            return
        self._running = False

        # Drain remaining events
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                await self._dispatch_to_subscribers(event)
            except asyncio.QueueEmpty:
                break

        if self._dispatch_task is not None:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
            self._dispatch_task = None

    async def publish(self, event: SecurityEvent) -> bool:
        """Publish a security event to the bus.

        Non-blocking. If the queue is full, applies the configured drop
        strategy and returns False if the incoming event was dropped.

        Args:
            event: The SecurityEvent to publish.

        Returns:
            True if the event was enqueued, False if it was dropped.
        """
        self._total_published += 1

        if self._queue.qsize() >= self._max_queue_size:
            if self._drop_strategy == "newest":
                # Drop the incoming event
                self._dropped_count += 1
                logger.warning(
                    "EventBus queue full (%d). Dropping incoming event %s (strategy=newest).",
                    self._max_queue_size,
                    event.event_id,
                )
                return False
            else:
                # Drop oldest: remove from front, put new at back
                try:
                    dropped = self._queue.get_nowait()
                    self._dropped_count += 1
                    logger.warning(
                        "EventBus queue full (%d). Dropping oldest event %s (strategy=oldest).",
                        self._max_queue_size,
                        dropped.event_id,
                    )
                except asyncio.QueueEmpty:
                    pass

        await self._queue.put(event)
        return True

    def subscribe(
        self,
        callback: Callable[[SecurityEvent], Awaitable[None]],
        filter_category: str | None = None,
        filter_severity: Severity | None = None,
    ) -> str:
        """Subscribe a callback to receive events matching the filter.

        Args:
            callback: Async function called for each matching event.
            filter_category: If set, only events with this category are delivered.
            filter_severity: If set, only events with severity >= this level are delivered.

        Returns:
            A subscription ID that can be used to unsubscribe.
        """
        sub_id = str(uuid.uuid4())
        event_filter = EventFilter(category=filter_category, min_severity=filter_severity)
        self._subscribers[sub_id] = _Subscription(
            subscription_id=sub_id,
            callback=callback,
            event_filter=event_filter,
        )
        return sub_id

    def unsubscribe(self, subscription_id: str) -> None:
        """Remove a subscription.

        Args:
            subscription_id: The ID returned by subscribe().

        Raises:
            KeyError: If the subscription ID is not found.
        """
        if subscription_id not in self._subscribers:
            raise KeyError(f"Unknown subscription: {subscription_id}")
        del self._subscribers[subscription_id]

    @property
    def stats(self) -> dict[str, Any]:
        """Return current event bus statistics.

        Returns:
            Dictionary with queue_size, dropped_count, total_published,
            and subscribers_count.
        """
        return {
            "queue_size": self._queue.qsize(),
            "dropped_count": self._dropped_count,
            "total_published": self._total_published,
            "subscribers_count": len(self._subscribers),
        }

    async def _dispatch_loop(self) -> None:
        """Main dispatch loop: get events from queue, dispatch to matching subscribers."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                await self._dispatch_to_subscribers(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in EventBus dispatch loop")

    async def _dispatch_to_subscribers(self, event: SecurityEvent) -> None:
        """Dispatch a single event to all matching subscribers.

        Args:
            event: The SecurityEvent to dispatch.
        """
        for sub in list(self._subscribers.values()):
            if sub.event_filter.matches(event):
                try:
                    await sub.callback(event)
                except Exception:
                    logger.exception(
                        "Error in subscriber %s callback for event %s",
                        sub.subscription_id,
                        event.event_id,
                    )
