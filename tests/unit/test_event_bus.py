"""Comprehensive tests for the async EventBus."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from guai.core.event_bus import EventBus
from guai.core.models import SecurityEvent
from guai.core.types import Severity


def _make_event(
    category: str = "network",
    severity: Severity = Severity.MEDIUM,
    source: str = "test_monitor",
    data: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Helper to create a SecurityEvent for testing."""
    return SecurityEvent.create(
        source=source,
        severity=severity,
        category=category,
        data=data or {},
    )


class TestPublishAndSubscribe:
    """Basic publish/subscribe functionality."""

    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self) -> None:
        """Published event is received by a subscriber."""
        bus = EventBus(max_queue_size=100)
        received: list[SecurityEvent] = []

        async def handler(event: SecurityEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        await bus.start()

        event = _make_event()
        result = await bus.publish(event)
        assert result is True

        # Give dispatch loop time to process
        await asyncio.sleep(0.2)
        await bus.stop()

        assert len(received) == 1
        assert received[0].event_id == event.event_id


class TestFilterByCategory:
    """Category-based filtering."""

    @pytest.mark.asyncio
    async def test_filter_by_category(self) -> None:
        """Subscriber with category filter only receives matching events."""
        bus = EventBus(max_queue_size=100)
        network_events: list[SecurityEvent] = []
        process_events: list[SecurityEvent] = []

        async def network_handler(event: SecurityEvent) -> None:
            network_events.append(event)

        async def process_handler(event: SecurityEvent) -> None:
            process_events.append(event)

        bus.subscribe(network_handler, filter_category="network")
        bus.subscribe(process_handler, filter_category="process")
        await bus.start()

        await bus.publish(_make_event(category="network"))
        await bus.publish(_make_event(category="process"))
        await bus.publish(_make_event(category="network"))
        await bus.publish(_make_event(category="auth"))  # nobody listens

        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(network_events) == 2
        assert len(process_events) == 1


class TestFilterBySeverity:
    """Severity-based filtering (>=)."""

    @pytest.mark.asyncio
    async def test_filter_by_severity(self) -> None:
        """Subscriber only gets events with severity >= threshold."""
        bus = EventBus(max_queue_size=100)
        high_events: list[SecurityEvent] = []

        async def handler(event: SecurityEvent) -> None:
            high_events.append(event)

        bus.subscribe(handler, filter_severity=Severity.HIGH)
        await bus.start()

        await bus.publish(_make_event(severity=Severity.LOW))
        await bus.publish(_make_event(severity=Severity.MEDIUM))
        await bus.publish(_make_event(severity=Severity.HIGH))
        await bus.publish(_make_event(severity=Severity.CRITICAL))

        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(high_events) == 2
        severities = {e.severity for e in high_events}
        assert severities == {Severity.HIGH, Severity.CRITICAL}


class TestBackPressureDropOldest:
    """Back-pressure with drop_strategy='oldest'."""

    @pytest.mark.asyncio
    async def test_back_pressure_drop_oldest(self) -> None:
        """When queue full with strategy=oldest, oldest events are dropped."""
        bus = EventBus(max_queue_size=3, drop_strategy="oldest")

        # Publish 5 events without starting the bus (no consumer)
        events = []
        for i in range(5):
            ev = _make_event(data={"seq": i})
            events.append(ev)
            result = await bus.publish(ev)
            # All should return True with "oldest" strategy
            assert result is True

        # 2 events were dropped (oldest), 3 remain in queue
        assert bus.stats["dropped_count"] == 2
        assert bus.stats["queue_size"] == 3

        # Start and drain to verify remaining events are the newest
        received: list[SecurityEvent] = []

        async def handler(event: SecurityEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        await bus.start()
        await asyncio.sleep(0.3)
        await bus.stop()

        # Remaining events should be seq 2, 3, 4 (oldest 0, 1 dropped)
        seqs = [e.data["seq"] for e in received]
        assert seqs == [2, 3, 4]


class TestBackPressureDropNewest:
    """Back-pressure with drop_strategy='newest'."""

    @pytest.mark.asyncio
    async def test_back_pressure_drop_newest(self) -> None:
        """When queue full with strategy=newest, incoming events are dropped."""
        bus = EventBus(max_queue_size=3, drop_strategy="newest")

        # Publish 5 events without starting the bus
        results = []
        events = []
        for i in range(5):
            ev = _make_event(data={"seq": i})
            events.append(ev)
            result = await bus.publish(ev)
            results.append(result)

        # First 3 accepted, last 2 dropped
        assert results == [True, True, True, False, False]
        assert bus.stats["dropped_count"] == 2
        assert bus.stats["queue_size"] == 3

        # Drain to verify remaining are the oldest (0, 1, 2)
        received: list[SecurityEvent] = []

        async def handler(event: SecurityEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        await bus.start()
        await asyncio.sleep(0.3)
        await bus.stop()

        seqs = [e.data["seq"] for e in received]
        assert seqs == [0, 1, 2]


class TestStatsTracking:
    """Stats tracking accuracy."""

    @pytest.mark.asyncio
    async def test_stats_tracking(self) -> None:
        """Stats correctly track total_published, dropped_count, and queue_size."""
        bus = EventBus(max_queue_size=5, drop_strategy="oldest")

        # Initial stats
        assert bus.stats == {
            "queue_size": 0,
            "dropped_count": 0,
            "total_published": 0,
            "subscribers_count": 0,
        }

        # Add a subscriber
        async def noop(event: SecurityEvent) -> None:
            pass

        sub_id = bus.subscribe(noop)
        assert bus.stats["subscribers_count"] == 1

        # Publish 8 events (5 fit, 3 overflow -> drop oldest)
        for _ in range(8):
            await bus.publish(_make_event())

        assert bus.stats["total_published"] == 8
        assert bus.stats["dropped_count"] == 3
        assert bus.stats["queue_size"] == 5

        # Unsubscribe
        bus.unsubscribe(sub_id)
        assert bus.stats["subscribers_count"] == 0


class TestBurstEvents:
    """High-volume burst publishing."""

    @pytest.mark.asyncio
    async def test_burst_events(self) -> None:
        """Publish 50000 events rapidly — no crash, stats correct."""
        bus = EventBus(max_queue_size=1000, drop_strategy="oldest")
        received_count = 0

        async def counter(event: SecurityEvent) -> None:
            nonlocal received_count
            received_count += 1

        bus.subscribe(counter)
        await bus.start()

        total = 50_000
        for i in range(total):
            await bus.publish(_make_event(data={"i": i}))

        # Allow dispatch loop to process
        await asyncio.sleep(1.0)
        await bus.stop()

        stats = bus.stats
        assert stats["total_published"] == total
        # received + dropped should equal total_published
        assert received_count + stats["dropped_count"] == total
        # Queue should be empty after stop()
        assert stats["queue_size"] == 0


class TestUnsubscribe:
    """Unsubscribe removes callback from dispatch."""

    @pytest.mark.asyncio
    async def test_unsubscribe(self) -> None:
        """Unsubscribed callback is not called for subsequent events."""
        bus = EventBus(max_queue_size=100)
        received: list[SecurityEvent] = []

        async def handler(event: SecurityEvent) -> None:
            received.append(event)

        sub_id = bus.subscribe(handler)
        await bus.start()

        # Publish one event — handler should get it
        await bus.publish(_make_event())
        await asyncio.sleep(0.2)
        assert len(received) == 1

        # Unsubscribe and publish another
        bus.unsubscribe(sub_id)
        await bus.publish(_make_event())
        await asyncio.sleep(0.2)
        await bus.stop()

        # Should still be only 1 event (not 2)
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe_unknown_raises(self) -> None:
        """Unsubscribing with an unknown ID raises KeyError."""
        bus = EventBus()
        with pytest.raises(KeyError):
            bus.unsubscribe("nonexistent-id")


class TestMultipleSubscribers:
    """Multiple subscribers each get their matching events."""

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self) -> None:
        """Multiple subscribers each receive events matching their filters."""
        bus = EventBus(max_queue_size=100)

        all_events: list[SecurityEvent] = []
        critical_events: list[SecurityEvent] = []
        auth_events: list[SecurityEvent] = []

        async def all_handler(event: SecurityEvent) -> None:
            all_events.append(event)

        async def critical_handler(event: SecurityEvent) -> None:
            critical_events.append(event)

        async def auth_handler(event: SecurityEvent) -> None:
            auth_events.append(event)

        # No filter — gets everything
        bus.subscribe(all_handler)
        # Only CRITICAL
        bus.subscribe(critical_handler, filter_severity=Severity.CRITICAL)
        # Only auth category
        bus.subscribe(auth_handler, filter_category="auth")

        await bus.start()

        await bus.publish(_make_event(category="network", severity=Severity.LOW))
        await bus.publish(_make_event(category="auth", severity=Severity.CRITICAL))
        await bus.publish(_make_event(category="process", severity=Severity.HIGH))
        await bus.publish(_make_event(category="auth", severity=Severity.MEDIUM))

        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(all_events) == 4
        assert len(critical_events) == 1
        assert critical_events[0].severity == Severity.CRITICAL
        assert len(auth_events) == 2
        assert all(e.category == "auth" for e in auth_events)


class TestEventBusLifecycle:
    """Start/stop lifecycle edge cases."""

    @pytest.mark.asyncio
    async def test_double_start(self) -> None:
        """Calling start() twice does not create duplicate dispatch loops."""
        bus = EventBus(max_queue_size=100)
        await bus.start()
        await bus.start()  # should be no-op
        await bus.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start(self) -> None:
        """Calling stop() without start() does not raise."""
        bus = EventBus(max_queue_size=100)
        await bus.stop()  # should be no-op

    @pytest.mark.asyncio
    async def test_invalid_drop_strategy(self) -> None:
        """Invalid drop_strategy raises ValueError."""
        with pytest.raises(ValueError, match="Invalid drop_strategy"):
            EventBus(drop_strategy="random")
