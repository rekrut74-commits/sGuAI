"""Integration tests for GuAIApp orchestrator."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml

from guai.core.app import GuAIApp
from guai.core.config import GuAIConfig
from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, Severity


@pytest.fixture
def integration_config(tmp_path: Path) -> GuAIConfig:
    """Create a GuAIConfig pointing at tmp dirs."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "guai.db"

    config_file = tmp_path / "guai.toml"
    config_file.write_text(
        f"""\
[general]
log_level = "DEBUG"
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
max_queue_size = 1000
drop_strategy = "oldest"

[alerts]
suppress_window_minutes = 5
max_alerts_per_minute = 50
enabled_channels = ["cli"]

[rules]
rules_dir = "{rules_dir.as_posix()}"
"""
    )
    return GuAIConfig.from_toml(config_file)


@pytest.fixture
def integration_config_with_rule(tmp_path: Path) -> GuAIConfig:
    """Config with a detection rule that matches test events."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "guai.db"

    # Write a rule that matches category "test"
    rule_data = {
        "name": "test_rule",
        "description": "Test rule for integration tests",
        "severity": 3,
        "source": "test",
        "conditions": {
            "category": "test",
        },
        "window_seconds": 0,
        "threshold": 1,
        "enabled": True,
    }
    rule_file = rules_dir / "test_rule.yaml"
    rule_file.write_text(yaml.dump(rule_data))

    config_file = tmp_path / "guai.toml"
    config_file.write_text(
        f"""\
[general]
log_level = "DEBUG"
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
max_queue_size = 1000
drop_strategy = "oldest"

[alerts]
suppress_window_minutes = 0
max_alerts_per_minute = 50
enabled_channels = []

[rules]
rules_dir = "{rules_dir.as_posix()}"
"""
    )
    return GuAIConfig.from_toml(config_file)


@pytest.mark.asyncio
async def test_app_initializes(integration_config: GuAIConfig) -> None:
    """GuAIApp initializes all modules without error."""
    app = GuAIApp(integration_config)
    await app.initialize()

    assert app._initialized
    assert app.event_bus is not None
    assert app.database is not None
    assert app.event_store is not None
    assert app.alert_store is not None
    assert app.rule_engine is not None
    assert app.alert_manager is not None
    assert app.scheduler is not None

    await app.database.close()


@pytest.mark.asyncio
async def test_app_health_check(integration_config: GuAIConfig) -> None:
    """Health check returns status for all modules."""
    app = GuAIApp(integration_config)
    await app.initialize()

    health = await app.health_check()

    assert "event_bus" in health
    assert "database" in health
    assert "rule_engine" in health
    assert "alert_manager" in health

    # Database should be healthy after init
    assert health["database"] == ModuleHealth.HEALTHY
    # Event bus not started yet, so STOPPED
    assert health["event_bus"] == ModuleHealth.STOPPED
    # Rule engine and alert manager are healthy after init
    assert health["rule_engine"] == ModuleHealth.HEALTHY
    assert health["alert_manager"] == ModuleHealth.HEALTHY

    await app.database.close()


@pytest.mark.asyncio
async def test_app_start_stop(integration_config: GuAIConfig) -> None:
    """App starts and stops gracefully within 3 seconds."""
    app = GuAIApp(integration_config)
    await app.initialize()
    await app.start()

    assert app._running

    health = await app.health_check()
    assert health["event_bus"] == ModuleHealth.HEALTHY

    # Give it a moment to settle
    await asyncio.sleep(0.1)

    # Stop with timeout
    try:
        await asyncio.wait_for(app.stop(), timeout=3.0)
    except asyncio.TimeoutError:
        pytest.fail("App did not stop within 3 seconds")

    assert not app._running


@pytest.mark.asyncio
async def test_event_pipeline(integration_config_with_rule: GuAIConfig) -> None:
    """Full pipeline: publish event -> rule matches -> alert created -> stored in DB."""
    app = GuAIApp(integration_config_with_rule)
    await app.initialize()
    await app.start()

    # Verify rule was loaded
    assert len(app.rule_engine.rules) == 1

    # Create and publish a test event that matches the rule
    event = SecurityEvent.create(
        source="test",
        severity=Severity.HIGH,
        category="test",
        data={"msg": "integration test event"},
    )
    await app.event_bus.publish(event)

    # Give the event bus time to dispatch and process
    await asyncio.sleep(0.5)

    # Verify event was stored
    stored_events = await app.event_store.query(limit=10)
    assert len(stored_events) >= 1
    found = any(e["event_id"] == event.event_id for e in stored_events)
    assert found, f"Event {event.event_id} not found in store"

    # Verify alert was created and stored
    stored_alerts = await app.alert_store.list_alerts(limit=10)
    assert len(stored_alerts) >= 1

    # Check alert references our event
    alert = stored_alerts[0]
    source_events = json.loads(alert["source_events"])
    assert event.event_id in source_events
    assert alert["rule_name"] == "test_rule"

    await app.stop()
