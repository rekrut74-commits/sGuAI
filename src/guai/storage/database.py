"""Async SQLite database wrapper with WAL mode for GuAI storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA = """\
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    severity INTEGER NOT NULL,
    category TEXT NOT NULL,
    data TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'untrusted',
    mitre_technique TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    severity INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source_events TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    mitre_technique TEXT,
    rule_name TEXT,
    acknowledged_by TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


class Database:
    """Async SQLite wrapper with WAL mode and convenience methods."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._connection: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create connection, set WAL mode, create tables and indices."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = await aiosqlite.connect(str(self.db_path))
        self._connection.row_factory = aiosqlite.Row

        # Enable WAL mode for better concurrency
        await self._connection.execute("PRAGMA journal_mode=WAL")
        # NORMAL synchronous is safe with WAL and faster than FULL
        await self._connection.execute("PRAGMA synchronous=NORMAL")

        # Create tables and indices
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    @property
    def connection(self) -> aiosqlite.Connection:
        """Return active connection or raise if not initialized."""
        if self._connection is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._connection

    async def execute(self, query: str, params: tuple[Any, ...] = ()) -> aiosqlite.Cursor:
        """Execute a single SQL statement and return cursor."""
        cursor = await self.connection.execute(query, params)
        await self.connection.commit()
        return cursor

    async def execute_many(self, query: str, params_list: list[tuple[Any, ...]]) -> None:
        """Execute the same SQL statement with multiple parameter sets."""
        await self.connection.executemany(query, params_list)
        await self.connection.commit()

    async def fetch_all(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Execute query and return all rows as list of dicts."""
        cursor = await self.connection.execute(query, params)
        rows = await cursor.fetchall()
        if not rows:
            return []
        columns = [desc[0] for desc in cursor.description]  # type: ignore[union-attr]
        return [dict(zip(columns, row)) for row in rows]

    async def fetch_one(self, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        """Execute query and return a single row as dict, or None."""
        cursor = await self.connection.execute(query, params)
        row = await cursor.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cursor.description]  # type: ignore[union-attr]
        return dict(zip(columns, row))

    async def __aenter__(self) -> Database:
        """Async context manager entry — initialize DB."""
        await self.initialize()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit — close DB."""
        await self.close()
