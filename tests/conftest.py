"""Pytest configuration and shared fixtures."""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio


@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """Create a temporary TOML config file."""
    config = tmp_path / "guai.toml"
    config.write_text("""\
[general]
log_level = "DEBUG"
data_dir = "{data_dir}"

[monitoring]
network_interval = 1.0
process_interval = 1.0
event_log_interval = 1.0
min_interval = 0.5
max_interval = 10.0
enabled_monitors = ["network", "process"]

[monitoring.event_log]
critical_event_ids = [4625, 1102]

[storage]
db_path = "{db_path}"
retention_days = 7
batch_size = 10

[event_bus]
max_queue_size = 1000
drop_strategy = "oldest"

[alerts]
suppress_window_minutes = 5
max_alerts_per_minute = 50
enabled_channels = ["cli"]

[rules]
rules_dir = "{rules_dir}"
""".format(
        data_dir=str(tmp_path / "data").replace("\\", "/"),
        db_path=str(tmp_path / "data" / "guai.db").replace("\\", "/"),
        rules_dir=str(tmp_path / "rules").replace("\\", "/"),
    ))
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "rules").mkdir(exist_ok=True)
    return config


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Return a temporary database path."""
    return tmp_path / "test_guai.db"
