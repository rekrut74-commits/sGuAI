"""Alerts command — lists security alerts from storage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncclick as click
from rich.console import Console
from rich.table import Table

from guai.core.app import GuAIApp
from guai.core.config import GuAIConfig
from guai.core.types import Severity


def _parse_since(since: str) -> str:
    """Parse a human-readable time range into an ISO-8601 timestamp.

    Supports formats like '1h', '24h', '7d', '30m'.

    Args:
        since: Time range string.

    Returns:
        ISO-8601 timestamp string.
    """
    now = datetime.now(tz=timezone.utc)
    value = since[:-1]
    unit = since[-1]

    try:
        num = int(value)
    except ValueError:
        return now.isoformat()

    if unit == "h":
        delta = timedelta(hours=num)
    elif unit == "d":
        delta = timedelta(days=num)
    elif unit == "m":
        delta = timedelta(minutes=num)
    else:
        delta = timedelta(hours=1)

    return (now - delta).isoformat()


_SEVERITY_STYLES: dict[int, str] = {
    Severity.LOW: "[blue]LOW[/blue]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.HIGH: "[red]HIGH[/red]",
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
}


@click.command()
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Filter by minimum severity.",
)
@click.option("--since", default="1h", help="Time range (1h, 24h, 7d)")
@click.option("--limit", default=50, help="Maximum number of alerts to display.")
@click.pass_context
async def alerts(
    ctx: click.Context,
    severity: str | None,
    since: str,
    limit: int,
) -> None:
    """List security alerts."""
    console = Console()
    config_path = ctx.obj["config_path"]

    try:
        config = GuAIConfig.from_toml(config_path)
    except Exception as exc:
        console.print(f"[red]Error loading config:[/red] {exc}")
        raise SystemExit(1)

    app = GuAIApp(config)
    try:
        await app.initialize()

        severity_val: int | None = None
        if severity is not None:
            severity_val = Severity[severity.upper()].value

        since_ts = _parse_since(since)

        rows = await app.alert_store.list_alerts(
            severity=severity_val,
            since=since_ts,
            limit=limit,
        )

        if not rows:
            console.print("[dim]No alerts found.[/dim]")
            return

        table = Table(title=f"Security Alerts (since {since})")
        table.add_column("Time", style="dim")
        table.add_column("Severity")
        table.add_column("Title", style="bold")
        table.add_column("Rule")
        table.add_column("Status")

        for row in rows:
            sev_int = row.get("severity", 1)
            sev_styled = _SEVERITY_STYLES.get(sev_int, str(sev_int))
            table.add_row(
                str(row.get("timestamp", ""))[:19],
                sev_styled,
                str(row.get("title", "")),
                str(row.get("rule_name", "")),
                str(row.get("status", "")),
            )

        console.print(table)
    finally:
        await app.database.close()
