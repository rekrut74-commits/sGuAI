"""Tests for guai.storage.event_store — event persistence layer."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from guai.storage.database import Database
from guai.storage.event_store import EventStore


# ---------- helpers ----------

def _make_event(
    *,
    event_id: str | None = None,
    timestamp: str | None = None,
    source: str = "test",
    severity: int = 5,
    category: str = "network",
    data: str = "{}",
    trust_level: str = "untrusted",
    mitre_technique: str | None = None,
) -> dict:
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "source": source,
        "severity": severity,
        "category": category,
        "data": data,
        "trust_level": trust_level,
        "mitre_technique": mitre_technique,
    }


@pytest_asyncio.fixture
async def store(tmp_db_path: Path) -> AsyncIterator[EventStore]:
    """Yield an EventStore backed by a temporary database."""
    db = Database(tmp_db_path)
    await db.initialize()
    es = EventStore(db)
    yield es  # type: ignore[misc]
    await db.close()


# ---------- tests ----------

@pytest.mark.asyncio
async def test_store_and_query(store: EventStore) -> None:
    """Store a single event and retrieve it."""
    await store.store(
        event_id="ev-1",
        timestamp="2025-06-01T12:00:00Z",
        source="sysmon",
        severity=7,
        category="process",
        data=json.dumps({"pid": 1234}),
    )
    rows = await store.query()
    assert len(rows) == 1
    assert rows[0]["event_id"] == "ev-1"
    assert rows[0]["severity"] == 7
    assert rows[0]["trust_level"] == "untrusted"


@pytest.mark.asyncio
async def test_store_batch(store: EventStore) -> None:
    """store_batch should insert 100 events in a single call."""
    events = [_make_event(event_id=f"batch-{i}") for i in range(100)]
    count = await store.store_batch(events)
    assert count == 100
    assert await store.count() == 100


@pytest.mark.asyncio
async def test_store_batch_empty(store: EventStore) -> None:
    """store_batch with empty list should return 0."""
    count = await store.store_batch([])
    assert count == 0


@pytest.mark.asyncio
async def test_query_filter_by_category(store: EventStore) -> None:
    """Query filtering by category should only return matching events."""
    events = [
        _make_event(event_id="cat-net", category="network"),
        _make_event(event_id="cat-auth", category="auth"),
        _make_event(event_id="cat-proc", category="process"),
        _make_event(event_id="cat-net2", category="network"),
    ]
    await store.store_batch(events)

    results = await store.query(category="network")
    assert len(results) == 2
    assert all(r["category"] == "network" for r in results)


@pytest.mark.asyncio
async def test_query_filter_by_severity(store: EventStore) -> None:
    """Query filtering by severity returns events with severity >= threshold."""
    events = [
        _make_event(event_id="sev-1", severity=1),
        _make_event(event_id="sev-5", severity=5),
        _make_event(event_id="sev-8", severity=8),
        _make_event(event_id="sev-10", severity=10),
    ]
    await store.store_batch(events)

    results = await store.query(severity=5)
    assert len(results) == 3
    assert all(r["severity"] >= 5 for r in results)


@pytest.mark.asyncio
async def test_query_filter_by_since(store: EventStore) -> None:
    """Query with since should filter old events."""
    events = [
        _make_event(event_id="old", timestamp="2024-01-01T00:00:00Z"),
        _make_event(event_id="new", timestamp="2025-06-01T00:00:00Z"),
    ]
    await store.store_batch(events)

    results = await store.query(since="2025-01-01T00:00:00Z")
    assert len(results) == 1
    assert results[0]["event_id"] == "new"


@pytest.mark.asyncio
async def test_cleanup_old_events(store: EventStore) -> None:
    """cleanup should delete events older than retention_days."""
    old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    recent_ts = datetime.now(timezone.utc).isoformat()

    events = [
        _make_event(event_id="old-ev", timestamp=old_ts),
        _make_event(event_id="recent-ev", timestamp=recent_ts),
    ]
    await store.store_batch(events)

    deleted = await store.cleanup(retention_days=30)
    assert deleted == 1
    assert await store.count() == 1

    remaining = await store.query()
    assert remaining[0]["event_id"] == "recent-ev"


@pytest.mark.asyncio
async def test_count(store: EventStore) -> None:
    """count() should reflect stored events."""
    assert await store.count() == 0
    await store.store_batch([_make_event() for _ in range(5)])
    assert await store.count() == 5


@pytest.mark.asyncio
@pytest.mark.slow
async def test_batch_performance(store: EventStore) -> None:
    """10 000 inserts via store_batch should complete under 2 seconds."""
    events = [_make_event(event_id=f"perf-{i}") for i in range(10_000)]

    start = time.monotonic()
    count = await store.store_batch(events)
    elapsed = time.monotonic() - start

    assert count == 10_000
    assert elapsed < 2.0, f"Batch insert took {elapsed:.2f}s, expected < 2s"
    assert await store.count() == 10_000
