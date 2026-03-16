"""Alert storage — create, query, acknowledge, resolve alerts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from guai.storage.database import Database


class AlertStore:
    """Persistent store for security alerts backed by SQLite."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(
        self,
        alert_id: str,
        timestamp: str,
        severity: int,
        title: str,
        description: str,
        source_events: str,
        status: str = "new",
        mitre_technique: str | None = None,
        rule_name: str | None = None,
    ) -> None:
        """Create a new alert."""
        await self.db.execute(
            """
            INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, severity, title, description,
                 source_events, status, mitre_technique, rule_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id, timestamp, severity, title, description,
                source_events, status, mitre_technique, rule_name,
            ),
        )

    async def get(self, alert_id: str) -> dict[str, Any] | None:
        """Get a single alert by ID."""
        return await self.db.fetch_one(
            "SELECT * FROM alerts WHERE alert_id = ?",
            (alert_id,),
        )

    async def list_alerts(
        self,
        *,
        status: str | None = None,
        severity: int | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List alerts with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if severity is not None:
            clauses.append("severity >= ?")
            params.append(severity)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)

        query = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return await self.db.fetch_all(query, tuple(params))

    async def acknowledge(self, alert_id: str, user: str) -> None:
        """Mark an alert as acknowledged by a user."""
        await self.db.execute(
            "UPDATE alerts SET status = 'acknowledged', acknowledged_by = ? WHERE alert_id = ?",
            (user, alert_id),
        )

    async def resolve(self, alert_id: str) -> None:
        """Mark an alert as resolved."""
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute(
            "UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE alert_id = ?",
            (now, alert_id),
        )

    async def count(self, status: str | None = None) -> int:
        """Count alerts, optionally filtered by status."""
        if status is not None:
            row = await self.db.fetch_one(
                "SELECT COUNT(*) AS cnt FROM alerts WHERE status = ?",
                (status,),
            )
        else:
            row = await self.db.fetch_one("SELECT COUNT(*) AS cnt FROM alerts")
        return row["cnt"] if row else 0
