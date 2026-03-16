"""GuAI CLI — main entry point."""

from __future__ import annotations

import asyncclick as click

from guai.cli.commands.alerts import alerts
from guai.cli.commands.start import start
from guai.cli.commands.status import status


@click.group()
@click.version_option(package_name="guai-system-guardian")
@click.option(
    "--config",
    default="config/guai.toml",
    envvar="GUAI_CONFIG",
    help="Path to GuAI TOML config file.",
)
@click.pass_context
async def cli(ctx: click.Context, config: str) -> None:
    """GuAI — System Guardian AI."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


cli.add_command(start)
cli.add_command(status)
cli.add_command(alerts)
