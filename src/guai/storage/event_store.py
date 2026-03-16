"""Event storage — insert, query, cleanup security events."""

from __future__ import annotations

from typing import Any

from guai.storage.database import Database


class EventStore:
    """Persistent store for security events backed by SQLite."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def store(
        self,
        event_id: str,
        timestamp: str,
        source: str,
        severity: int,
        category: str,
        data: str,
        trust_level: str = "untrusted",
        mitre_technique: str | None = None,
    ) -> None:
        """Store a single event."""
        await self.db.execute(
            """
            INSERT OR REPLACE INTO events
                (event_id, timestamp, source, severity, category, data, trust_level, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, timestamp, source, severity, category, data, trust_level, mitre_technique),
        )

    async def store_batch(self, events: list[dict[str, Any]]) -> int:
        """Store a batch of events in a single transaction.

        Each dict must contain keys: event_id, timestamp, source, severity,
        category, data.  Optional: trust_level, mitre_technique.

        Returns the number of events stored.
        """
        if not events:
            return 0

        params_list: list[tuple[Any, ...]] = [
            (
                e["event_id"],
                e["timestamp"],
                e["source"],
                e["severity"],
                e["category"],
                e["data"],
                e.get("trust_level", "untrusted"),
                e.get("mitre_technique"),
            )
            for e in events
        ]
        await self.db.execute_many(
            """
            INSERT OR REPLACE INTO events
                (event_id, timestamp, source, severity, category, data, trust_level, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            params_list,
        )
        return len(params_list)

    async def query(
        self,
        *,
        since: str | None = None,
        category: str | None = None,
        severity: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query events with optional filters.

        Parameters
        ----------
        since:
            ISO-8601 timestamp — return events at or after this time.
        category:
            Filter by event category.
        severity:
            Minimum severity (inclusive).
        limit:
            Max rows to return (default 100).
        """
        clauses: list[str] = []
        params: list[Any] = []

        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if severity is not None:
            clauses.append("severity >= ?")
            params.append(severity)

        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)

        query_sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return await self.db.fetch_all(query_sql, tuple(params))

    async def count(self) -> int:
        """Return total number of events in the store."""
        row = await self.db.fetch_one("SELECT COUNT(*) AS cnt FROM events")
        return row["cnt"] if row else 0

    async def cleanup(self, retention_days: int = 30) -> int:
        """Delete events older than *retention_days*.

        Returns the number of deleted rows.
        """
        cursor = await self.db.execute(
            """
            DELETE FROM events
            WHERE timestamp < datetime('now', ? || ' days')
            """,
            (str(-retention_days),),
        )
        return cursor.rowcount
