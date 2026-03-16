"""Tests for GuAI configuration loading and validation."""

from pathlib import Path

import pytest

from guai.core.config import GuAIConfig
from guai.core.exceptions import ConfigError


class TestGuAIConfigFromToml:
    """Loading configuration from a valid TOML file."""

    def test_loads_valid_config(self, tmp_config: Path) -> None:
        cfg = GuAIConfig.from_toml(tmp_config)
        assert cfg.general.log_level == "DEBUG"
        assert cfg.monitoring.network_interval == 1.0
        assert cfg.monitoring.process_interval == 1.0
        assert cfg.monitoring.event_log_interval == 1.0
        assert cfg.monitoring.enabled_monitors == ["network", "process"]
        assert cfg.monitoring.event_log.critical_event_ids == [4625, 1102]
        assert cfg.storage.retention_days == 7
        assert cfg.storage.batch_size == 10
        assert cfg.event_bus.max_queue_size == 1000
        assert cfg.event_bus.drop_strategy == "oldest"
        assert cfg.alerts.suppress_window_minutes == 5
        assert cfg.alerts.max_alerts_per_minute == 50
        assert cfg.alerts.enabled_channels == ["cli"]

    def test_data_dir_from_toml(self, tmp_config: Path) -> None:
        cfg = GuAIConfig.from_toml(tmp_config)
        # The fixture sets data_dir to a tmp_path-based directory
        assert "data" in cfg.general.data_dir

    def test_rules_dir_from_toml(self, tmp_config: Path) -> None:
        cfg = GuAIConfig.from_toml(tmp_config)
        assert "rules" in cfg.rules.rules_dir


class TestGuAIConfigDefaults:
    """Default values when no TOML is provided."""

    def test_defaults(self) -> None:
        cfg = GuAIConfig()
        assert cfg.general.log_level == "INFO"
        assert cfg.general.data_dir == "data"
        assert cfg.monitoring.network_interval == 5.0
        assert cfg.monitoring.process_interval == 5.0
        assert cfg.monitoring.event_log_interval == 3.0
        assert cfg.monitoring.min_interval == 0.5
        assert cfg.monitoring.max_interval == 30.0
        assert cfg.monitoring.enabled_monitors == ["network", "process", "event_log"]
        assert cfg.monitoring.event_log.critical_event_ids == [4625, 4688, 1102, 7045, 4697]
        assert cfg.storage.db_path == "data/guai.db"
        assert cfg.storage.retention_days == 30
        assert cfg.storage.batch_size == 50
        assert cfg.event_bus.max_queue_size == 10000
        assert cfg.event_bus.drop_strategy == "oldest"
        assert cfg.alerts.suppress_window_minutes == 15
        assert cfg.alerts.max_alerts_per_minute == 100
        assert cfg.alerts.enabled_channels == ["cli"]
        assert cfg.rules.rules_dir == "config/rules"


class TestGuAIConfigValidation:
    """Validation errors for invalid configuration values."""

    def test_invalid_log_level(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.toml"
        cfg_file.write_text('[general]\nlog_level = "BANANA"\n')
        with pytest.raises(ConfigError, match="Config validation error"):
            GuAIConfig.from_toml(cfg_file)

    def test_negative_interval(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.toml"
        cfg_file.write_text("[monitoring]\nnetwork_interval = -1.0\n")
        with pytest.raises(ConfigError, match="Config validation error"):
            GuAIConfig.from_toml(cfg_file)

    def test_max_interval_lt_min_interval(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.toml"
        cfg_file.write_text("[monitoring]\nmin_interval = 10.0\nmax_interval = 1.0\n")
        with pytest.raises(ConfigError, match="Config validation error"):
            GuAIConfig.from_toml(cfg_file)

    def test_invalid_drop_strategy(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.toml"
        cfg_file.write_text('[event_bus]\ndrop_strategy = "random"\n')
        with pytest.raises(ConfigError, match="Config validation error"):
            GuAIConfig.from_toml(cfg_file)

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            GuAIConfig.from_toml(tmp_path / "nonexistent.toml")

    def test_invalid_toml_syntax(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "broken.toml"
        cfg_file.write_text("this is [[[not valid toml")
        with pytest.raises(ConfigError, match="Invalid TOML"):
            GuAIConfig.from_toml(cfg_file)

    def test_zero_retention_days(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.toml"
        cfg_file.write_text("[storage]\nretention_days = 0\n")
        with pytest.raises(ConfigError, match="Config validation error"):
            GuAIConfig.from_toml(cfg_file)
