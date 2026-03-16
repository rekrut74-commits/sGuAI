"""Status command — shows system health."""

from __future__ import annotations

import asyncclick as click
from rich.console import Console
from rich.table import Table

from guai.core.app import GuAIApp
from guai.core.config import GuAIConfig
from guai.core.types import ModuleHealth


_HEALTH_STYLES: dict[ModuleHealth, str] = {
    ModuleHealth.HEALTHY: "[green]HEALTHY[/green]",
    ModuleHealth.DEGRADED: "[yellow]DEGRADED[/yellow]",
    ModuleHealth.UNHEALTHY: "[red]UNHEALTHY[/red]",
    ModuleHealth.STOPPED: "[dim]STOPPED[/dim]",
}


@click.command()
@click.pass_context
async def status(ctx: click.Context) -> None:
    """Show system status."""
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
        health = await app.health_check()

        table = Table(title="GuAI System Status")
        table.add_column("Module", style="bold")
        table.add_column("Health")

        for module_name, module_health in health.items():
            styled = _HEALTH_STYLES.get(module_health, str(module_health.value))
            table.add_row(module_name, styled)

        # Event bus stats
        stats = app.event_bus.stats
        table.add_section()
        table.add_row("Events published", str(stats["total_published"]))
        table.add_row("Events dropped", str(stats["dropped_count"]))
        table.add_row("Queue size", str(stats["queue_size"]))
        table.add_row("Rules loaded", str(len(app.rule_engine.rules)))

        console.print(table)
    finally:
        await app.database.close()
