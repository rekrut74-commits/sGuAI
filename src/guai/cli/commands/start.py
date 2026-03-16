"""Start command — launches GuAI system monitoring."""

from __future__ import annotations

import asyncio
import signal
import sys

import asyncclick as click
from rich.console import Console
from rich.panel import Panel

from guai.core.app import GuAIApp
from guai.core.config import GuAIConfig


@click.command()
@click.pass_context
async def start(ctx: click.Context) -> None:
    """Start GuAI system monitoring."""
    console = Console()
    config_path = ctx.obj["config_path"]

    try:
        config = GuAIConfig.from_toml(config_path)
    except Exception as exc:
        console.print(f"[red]Error loading config:[/red] {exc}")
        raise SystemExit(1)

    app = GuAIApp(config)

    # Banner
    banner = Panel(
        "[bold green]GuAI — System Guardian AI[/bold green]\n"
        f"Config: {config_path}\n"
        f"Monitors: {', '.join(config.monitoring.enabled_monitors)}\n"
        f"Log level: {config.general.log_level}",
        title="GuAI v0.1.0",
        border_style="green",
        expand=False,
    )
    console.print(banner)

    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        console.print("\n[yellow]Received shutdown signal...[/yellow]")
        stop_event.set()

    # Register signal handlers (only on platforms that support it)
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)
    # On Windows, KeyboardInterrupt is caught by the except block below

    try:
        await app.initialize()
        await app.start()
        console.print("[green]GuAI is running. Press Ctrl+C to stop.[/green]")

        # Wait for shutdown signal
        await stop_event.wait()

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Fatal error:[/red] {exc}")
        raise SystemExit(1)
    finally:
        await app.stop()
        console.print("[green]GuAI stopped.[/green]")
