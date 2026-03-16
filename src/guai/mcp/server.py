"""MCP server for GuAI System Guardian — exposes security monitoring tools.

Run standalone:
    python -m guai.mcp.server

Or create programmatically:
    from guai.mcp.server import create_mcp_server
    server = create_mcp_server()
    server.run()
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from guai.core.config import GuAIConfig
from guai.core.types import AlertStatus, Severity
from guai.mcp.tools import format_alerts, format_events, parse_since
from guai.rules.engine import RuleEngine
from guai.storage.alert_store import AlertStore
from guai.storage.database import Database
from guai.storage.event_store import EventStore

mcp = FastMCP("guai", instructions="GuAI System Guardian — security monitoring tools")


def _get_config_path() -> str:
    """Return the config path from env or default."""
    return os.environ.get("GUAI_CONFIG", "config/guai.toml")


def _load_config() -> GuAIConfig:
    """Load GuAI config, falling back to defaults if file not found."""
    config_path = _get_config_path()
    if Path(config_path).exists():
        return GuAIConfig.from_toml(config_path)
    return GuAIConfig()


def _get_db_path() -> str:
    """Resolve the database path from config."""
    config = _load_config()
    return config.storage.db_path


def _db_exists() -> bool:
    """Check if the database file exists."""
    return Path(_get_db_path()).exists()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def guai_status() -> str:
    """Get GuAI system status -- monitor health, event counts, alert counts."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps(
            {
                "status": "no_database",
                "message": f"Database not found at '{db_path}'. "
                "GuAI may not have been started yet.",
            },
            indent=2,
        )

    try:
        async with Database(db_path) as db:
            event_store = EventStore(db)
            alert_store = AlertStore(db)

            event_count = await event_store.count()
            alert_total = await alert_store.count()
            alert_new = await alert_store.count(status="new")
            alert_ack = await alert_store.count(status="acknowledged")

            config = _load_config()
            rules_dir = config.rules.rules_dir
            engine = RuleEngine()
            rules_loaded = engine.load_rules(rules_dir) if Path(rules_dir).is_dir() else 0

            return json.dumps(
                {
                    "status": "ok",
                    "database": db_path,
                    "events_total": event_count,
                    "alerts_total": alert_total,
                    "alerts_new": alert_new,
                    "alerts_acknowledged": alert_ack,
                    "rules_loaded": rules_loaded,
                },
                indent=2,
            )
    except Exception as exc:
        return json.dumps({"status": "error", "message": str(exc)}, indent=2)


@mcp.tool()
async def guai_events(
    since: str = "1h",
    severity: str | None = None,
    category: str | None = None,
    limit: int = 20,
) -> str:
    """Query security events. since: time range (1h, 24h, 7d). Returns JSON."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps(
            {"error": f"Database not found at '{db_path}'."},
            indent=2,
        )

    try:
        since_dt = parse_since(since)
        severity_int: int | None = None
        if severity is not None:
            try:
                severity_int = Severity[severity.upper()].value
            except KeyError:
                return json.dumps(
                    {
                        "error": f"Invalid severity '{severity}'. "
                        f"Valid values: {', '.join(s.name for s in Severity)}",
                    },
                    indent=2,
                )

        async with Database(db_path) as db:
            event_store = EventStore(db)
            events = await event_store.query(
                since=since_dt.isoformat(),
                category=category,
                severity=severity_int,
                limit=limit,
            )
            return format_events(events)

    except ValueError as exc:
        return json.dumps({"error": str(exc)}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_alerts(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 20,
) -> str:
    """List security alerts. Filter by severity (LOW/MEDIUM/HIGH/CRITICAL) and status (new/acknowledged/resolved)."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps(
            {"error": f"Database not found at '{db_path}'."},
            indent=2,
        )

    try:
        severity_int: int | None = None
        if severity is not None:
            try:
                severity_int = Severity[severity.upper()].value
            except KeyError:
                return json.dumps(
                    {
                        "error": f"Invalid severity '{severity}'. "
                        f"Valid values: {', '.join(s.name for s in Severity)}",
                    },
                    indent=2,
                )

        # Validate status if provided
        if status is not None:
            valid_statuses = {s.value for s in AlertStatus}
            if status.lower() not in valid_statuses:
                return json.dumps(
                    {
                        "error": f"Invalid status '{status}'. "
                        f"Valid values: {', '.join(valid_statuses)}",
                    },
                    indent=2,
                )
            status = status.lower()

        async with Database(db_path) as db:
            alert_store = AlertStore(db)
            alerts = await alert_store.list_alerts(
                severity=severity_int,
                status=status,
                limit=limit,
            )
            return format_alerts(alerts)

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_alert_ack(alert_id: str) -> str:
    """Acknowledge a security alert by ID."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps(
            {"error": f"Database not found at '{db_path}'."},
            indent=2,
        )

    try:
        async with Database(db_path) as db:
            alert_store = AlertStore(db)

            # Check if alert exists
            alert = await alert_store.get(alert_id)
            if alert is None:
                return json.dumps(
                    {"error": f"Alert '{alert_id}' not found."},
                    indent=2,
                )

            await alert_store.acknowledge(alert_id, user="mcp")
            return json.dumps(
                {
                    "status": "acknowledged",
                    "alert_id": alert_id,
                    "message": f"Alert '{alert_id}' acknowledged by MCP user.",
                },
                indent=2,
            )

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_rules() -> str:
    """List all active detection rules."""
    try:
        config = _load_config()
        rules_dir = config.rules.rules_dir

        if not Path(rules_dir).is_dir():
            return json.dumps(
                {
                    "rules": [],
                    "count": 0,
                    "message": f"Rules directory '{rules_dir}' not found.",
                },
                indent=2,
            )

        engine = RuleEngine()
        loaded = engine.load_rules(rules_dir)

        rules_data: list[dict[str, Any]] = []
        for rule in engine.rules:
            rules_data.append(
                {
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity.name,
                    "source": rule.source,
                    "conditions": rule.conditions,
                    "window_seconds": rule.window_seconds,
                    "threshold": rule.threshold,
                    "mitre_technique": rule.mitre_technique,
                    "enabled": rule.enabled,
                }
            )

        return json.dumps(
            {"rules": rules_data, "count": loaded},
            indent=2,
            default=str,
        )

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_event_stats() -> str:
    """Get event statistics -- counts by category, severity, time range."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps(
            {"error": f"Database not found at '{db_path}'."},
            indent=2,
        )

    try:
        async with Database(db_path) as db:
            # Count by category
            by_category = await db.fetch_all(
                "SELECT category, COUNT(*) AS cnt FROM events GROUP BY category ORDER BY cnt DESC"
            )
            # Count by severity
            by_severity = await db.fetch_all(
                "SELECT severity, COUNT(*) AS cnt FROM events GROUP BY severity ORDER BY severity DESC"
            )
            # Time ranges
            event_store = EventStore(db)
            total = await event_store.count()

            last_1h = parse_since("1h").isoformat()
            last_24h = parse_since("24h").isoformat()
            last_7d = parse_since("7d").isoformat()

            count_1h = await db.fetch_one(
                "SELECT COUNT(*) AS cnt FROM events WHERE timestamp >= ?",
                (last_1h,),
            )
            count_24h = await db.fetch_one(
                "SELECT COUNT(*) AS cnt FROM events WHERE timestamp >= ?",
                (last_24h,),
            )
            count_7d = await db.fetch_one(
                "SELECT COUNT(*) AS cnt FROM events WHERE timestamp >= ?",
                (last_7d,),
            )

            return json.dumps(
                {
                    "total_events": total,
                    "by_category": {row["category"]: row["cnt"] for row in by_category},
                    "by_severity": {str(row["severity"]): row["cnt"] for row in by_severity},
                    "last_1h": count_1h["cnt"] if count_1h else 0,
                    "last_24h": count_24h["cnt"] if count_24h else 0,
                    "last_7d": count_7d["cnt"] if count_7d else 0,
                },
                indent=2,
            )

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_perf_top(limit: int = 10) -> str:
    """Top processes by CPU usage from latest performance snapshot."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps({"error": "Database not found."}, indent=2)

    try:
        since_dt = parse_since("5m")
        async with Database(db_path) as db:
            event_store = EventStore(db)
            events = await event_store.query(
                category="performance", limit=200, since=since_dt.isoformat()
            )

        if not events:
            return json.dumps({"processes": [], "message": "No performance data yet"}, indent=2)

        # Deduplicate by PID — keep latest
        by_pid: dict[int, dict[str, Any]] = {}
        for e in events:
            data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
            pid = data.get("pid")
            if pid is not None:
                by_pid[pid] = data

        top = sorted(by_pid.values(), key=lambda d: d.get("cpu_percent", 0), reverse=True)[
            :limit
        ]
        return json.dumps({"processes": top, "count": len(top)}, indent=2)

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_bandwidth(since: str = "5m") -> str:
    """Current bandwidth stats per interface."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps({"error": "Database not found."}, indent=2)

    try:
        since_dt = parse_since(since)
        async with Database(db_path) as db:
            event_store = EventStore(db)
            events = await event_store.query(
                category="bandwidth", limit=50, since=since_dt.isoformat()
            )

        if not events:
            return json.dumps(
                {"interfaces": [], "message": "No bandwidth data yet"}, indent=2
            )

        by_iface: dict[str, dict[str, Any]] = {}
        for e in events:
            data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
            iface = data.get("interface")
            if iface:
                by_iface[iface] = data

        return json.dumps({"interfaces": list(by_iface.values())}, indent=2)

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
async def guai_latency(since: str = "5m") -> str:
    """Latest latency measurements per target."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        return json.dumps({"error": "Database not found."}, indent=2)

    try:
        since_dt = parse_since(since)
        async with Database(db_path) as db:
            event_store = EventStore(db)
            events = await event_store.query(
                category="latency", limit=50, since=since_dt.isoformat()
            )

        if not events:
            return json.dumps({"targets": [], "message": "No latency data yet"}, indent=2)

        by_target: dict[str, dict[str, Any]] = {}
        for e in events:
            data = json.loads(e["data"]) if isinstance(e["data"], str) else e["data"]
            target = data.get("target")
            if target:
                by_target[target] = data

        return json.dumps({"targets": list(by_target.values())}, indent=2)

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


@mcp.resource("guai://config")
async def get_config() -> str:
    """Current GuAI configuration."""
    try:
        config = _load_config()
        return json.dumps(config.model_dump(), indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.resource("guai://rules/{rule_name}")
async def get_rule(rule_name: str) -> str:
    """Get a specific detection rule by name."""
    try:
        config = _load_config()
        rules_dir = config.rules.rules_dir

        if not Path(rules_dir).is_dir():
            return json.dumps(
                {"error": f"Rules directory '{rules_dir}' not found."},
                indent=2,
            )

        engine = RuleEngine()
        engine.load_rules(rules_dir)

        for rule in engine.rules:
            if rule.name == rule_name:
                return json.dumps(
                    {
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.name,
                        "source": rule.source,
                        "conditions": rule.conditions,
                        "window_seconds": rule.window_seconds,
                        "threshold": rule.threshold,
                        "mitre_technique": rule.mitre_technique,
                        "enabled": rule.enabled,
                    },
                    indent=2,
                    default=str,
                )

        return json.dumps(
            {"error": f"Rule '{rule_name}' not found."},
            indent=2,
        )

    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


# ---------------------------------------------------------------------------
# Factory & entry point
# ---------------------------------------------------------------------------


def create_mcp_server() -> FastMCP:
    """Create and return the configured MCP server instance."""
    return mcp


if __name__ == "__main__":
    mcp.run()
