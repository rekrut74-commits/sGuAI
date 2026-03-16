"""Integration tests for CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from asyncclick.testing import CliRunner

from guai.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def cli_config(tmp_path: Path) -> Path:
    """Create a minimal config file for CLI tests."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    db_path = data_dir / "guai.db"

    config_file = tmp_path / "guai.toml"
    config_file.write_text(
        f"""\
[general]
log_level = "WARNING"
data_dir = "{data_dir.as_posix()}"

[monitoring]
network_interval = 60.0
process_interval = 60.0
event_log_interval = 60.0
min_interval = 0.5
max_interval = 60.0
enabled_monitors = []

[storage]
db_path = "{db_path.as_posix()}"
retention_days = 7
batch_size = 10

[event_bus]
max_queue_size = 100
drop_strategy = "oldest"

[alerts]
suppress_window_minutes = 5
max_alerts_per_minute = 50
enabled_channels = []

[rules]
rules_dir = "{rules_dir.as_posix()}"
"""
    )
    return config_file


@pytest.mark.asyncio
async def test_cli_help(runner: CliRunner) -> None:
    """'guai --help' outputs help text."""
    result = await runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "GuAI" in result.output
    assert "System Guardian AI" in result.output


@pytest.mark.asyncio
async def test_cli_version(runner: CliRunner) -> None:
    """'guai --version' shows version."""
    result = await runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


@pytest.mark.asyncio
async def test_status_command(runner: CliRunner, cli_config: Path) -> None:
    """'guai status' runs without crash and shows system status."""
    result = await runner.invoke(cli, ["--config", str(cli_config), "status"])
    assert result.exit_code == 0
    assert "Status" in result.output or "status" in result.output.lower()


@pytest.mark.asyncio
async def test_alerts_command(runner: CliRunner, cli_config: Path) -> None:
    """'guai alerts' runs without crash."""
    result = await runner.invoke(cli, ["--config", str(cli_config), "alerts"])
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_start_help(runner: CliRunner) -> None:
    """'guai start --help' shows start command help."""
    result = await runner.invoke(cli, ["start", "--help"])
    assert result.exit_code == 0
    assert "Start" in result.output or "start" in result.output.lower()
