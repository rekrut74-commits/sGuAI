"""Tests for guai.storage.database — async SQLite wrapper."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from guai.storage.database import Database


# ---------- helpers ----------

@pytest_asyncio.fixture
async def db(tmp_db_path: Path) -> AsyncIterator[Database]:
    """Yield an initialised Database and close it after the test."""
    database = Database(tmp_db_path)
    await database.initialize()
    yield database  # type: ignore[misc]
    await database.close()


# ---------- tests ----------

@pytest.mark.asyncio
async def test_initialize_creates_tables(db: Database) -> None:
    """After initialize(), both events and alerts tables must exist."""
    tables = await db.fetch_all(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    table_names = {row["name"] for row in tables}
    assert "events" in table_names
    assert "alerts" in table_names


@pytest.mark.asyncio
async def test_wal_mode_enabled(db: Database) -> None:
    """WAL journal mode must be active after initialize()."""
    row = await db.fetch_one("PRAGMA journal_mode")
    assert row is not None
    # The value can be returned under different key names depending on driver.
    journal_mode = list(row.values())[0]
    assert journal_mode.lower() == "wal"


@pytest.mark.asyncio
async def test_execute_and_fetch(db: Database) -> None:
    """Basic insert + fetch round-trip."""
    await db.execute(
        "INSERT INTO events (event_id, timestamp, source, severity, category, data) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("e1", "2025-01-01T00:00:00Z", "test", 5, "auth", '{"key": "val"}'),
    )
    row = await db.fetch_one("SELECT * FROM events WHERE event_id = ?", ("e1",))
    assert row is not None
    assert row["event_id"] == "e1"
    assert row["severity"] == 5


@pytest.mark.asyncio
async def test_execute_many(db: Database) -> None:
    """execute_many should batch-insert multiple rows."""
    params = [
        (f"e{i}", "2025-01-01T00:00:00Z", "test", i, "network", "{}")
        for i in range(10)
    ]
    await db.execute_many(
        "INSERT INTO events (event_id, timestamp, source, severity, category, data) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        params,
    )
    rows = await db.fetch_all("SELECT * FROM events")
    assert len(rows) == 10


@pytest.mark.asyncio
async def test_context_manager(tmp_db_path: Path) -> None:
    """Database should work as async context manager."""
    async with Database(tmp_db_path) as db:
        tables = await db.fetch_all(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        assert len(tables) > 0

    # After exiting, connection should be closed
    assert db._connection is None


@pytest.mark.asyncio
async def test_fetch_one_returns_none(db: Database) -> None:
    """fetch_one should return None when no rows match."""
    row = await db.fetch_one("SELECT * FROM events WHERE event_id = ?", ("nonexistent",))
    assert row is None


@pytest.mark.asyncio
async def test_fetch_all_returns_empty_list(db: Database) -> None:
    """fetch_all should return empty list on no results."""
    rows = await db.fetch_all("SELECT * FROM events")
    assert rows == []
