"""Rich Live dashboard for real-time monitoring."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.table import Table

if TYPE_CHECKING:
    from guai.core.app import GuAIApp


class Dashboard:
    """Rich Live dashboard for monitoring.

    Renders current system status as a rich Table suitable for
    use with ``rich.live.Live`` for periodic refreshing.
    """

    def __init__(self, app: GuAIApp) -> None:
        self.app = app

    def render(self) -> Table:
        """Render current status as a rich Table.

        Returns:
            A Table showing monitor health, event bus stats, and alert count.
        """
        table = Table(
            title="GuAI Dashboard",
            caption=f"Updated: {datetime.now(tz=timezone.utc).strftime('%H:%M:%S UTC')}",
        )
        table.add_column("Component", style="bold")
        table.add_column("Status")
        table.add_column("Details")

        # Monitors
        for monitor in self.app.monitors:
            health = monitor.health
            if health.value == "healthy":
                style = "[green]HEALTHY[/green]"
            elif health.value == "degraded":
                style = "[yellow]DEGRADED[/yellow]"
            elif health.value == "unhealthy":
                style = "[red]UNHEALTHY[/red]"
            else:
                style = "[dim]STOPPED[/dim]"

            table.add_row(
                f"Monitor: {monitor.monitor_type.value}",
                style,
                "",
            )

        # Event bus stats
        if hasattr(self.app, "event_bus"):
            stats = self.app.event_bus.stats
            table.add_section()
            table.add_row(
                "Event Bus",
                "[green]RUNNING[/green]" if self.app.event_bus._running else "[dim]STOPPED[/dim]",
                f"queue={stats['queue_size']} pub={stats['total_published']} drop={stats['dropped_count']}",
            )

        # Alert manager
        if hasattr(self.app, "alert_manager"):
            table.add_row(
                "Alert Manager",
                "[green]ACTIVE[/green]",
                f"alerts_sent={self.app.alert_manager.alert_count}",
            )

        # Rule engine
        if hasattr(self.app, "rule_engine"):
            table.add_row(
                "Rule Engine",
                "[green]ACTIVE[/green]",
                f"rules={len(self.app.rule_engine.rules)}",
            )

        # Scheduler
        if hasattr(self.app, "scheduler"):
            tasks = self.app.scheduler.running_tasks
            table.add_row(
                "Scheduler",
                "[green]RUNNING[/green]" if tasks else "[dim]IDLE[/dim]",
                f"tasks={', '.join(tasks) if tasks else 'none'}",
            )

        return table
