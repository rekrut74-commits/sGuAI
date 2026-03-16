"""Alert channels — delivery mechanisms for security alerts."""

from __future__ import annotations

from abc import ABC, abstractmethod

from rich.console import Console
from rich.panel import Panel

from guai.core.models import Alert
from guai.core.types import Severity


class AlertChannel(ABC):
    """Abstract base class for alert delivery channels."""

    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        """Send an alert through this channel.

        Args:
            alert: The alert to deliver.

        Returns:
            True if the alert was sent successfully.
        """
        ...


class CLIChannel(AlertChannel):
    """Display alerts in the terminal using rich.

    Colors are based on severity:
    - LOW: blue
    - MEDIUM: yellow
    - HIGH: red
    - CRITICAL: bold red
    """

    _SEVERITY_STYLES: dict[Severity, str] = {
        Severity.LOW: "blue",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red",
    }

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    async def send(self, alert: Alert) -> bool:
        """Display an alert as a rich panel in the terminal.

        Args:
            alert: The alert to display.

        Returns:
            True if the alert was displayed successfully.
        """
        style = self._SEVERITY_STYLES.get(alert.severity, "white")
        severity_name = alert.severity.name

        body_lines = [
            f"[bold]Severity:[/bold] {severity_name}",
            f"[bold]Description:[/bold] {alert.description}",
        ]
        if alert.rule_name:
            body_lines.append(f"[bold]Rule:[/bold] {alert.rule_name}")
        if alert.mitre_technique:
            body_lines.append(f"[bold]MITRE:[/bold] {alert.mitre_technique}")
        if alert.source_events:
            body_lines.append(f"[bold]Events:[/bold] {len(alert.source_events)}")

        body = "\n".join(body_lines)

        panel = Panel(
            body,
            title=f"ALERT: {alert.title}",
            border_style=style,
            expand=False,
        )
        self._console.print(panel)
        return True
