"""Configuration management for GuAI system.

Loads settings from a TOML file with pydantic-settings validation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings

from guai.core.exceptions import ConfigError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


class EventLogConfig(BaseModel):
    """Event log monitoring sub-configuration."""

    critical_event_ids: list[int] = Field(
        default_factory=lambda: [4625, 4688, 1102, 7045, 4697],
        description="Windows Event IDs considered critical",
    )


class GeneralConfig(BaseModel):
    """General application settings."""

    log_level: str = Field(default="INFO", description="Logging level")
    data_dir: str = Field(default="data", description="Directory for persistent data")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            msg = f"Invalid log_level '{v}'. Must be one of: {', '.join(sorted(allowed))}"
            raise ValueError(msg)
        return upper


class MonitoringConfig(BaseModel):
    """Monitoring intervals and settings."""

    network_interval: float = Field(default=5.0, gt=0, description="Network sampling interval (s)")
    process_interval: float = Field(default=5.0, gt=0, description="Process sampling interval (s)")
    event_log_interval: float = Field(
        default=3.0, gt=0, description="Event log polling interval (s)"
    )
    wifi_interval: float = Field(default=10.0, gt=0, description="WiFi scan interval (s)")
    bluetooth_interval: float = Field(default=15.0, gt=0, description="Bluetooth scan interval (s)")
    dns_interval: float = Field(default=10.0, gt=0, description="DNS cache poll interval (s)")
    min_interval: float = Field(
        default=0.5, gt=0, description="Minimum adaptive sampling interval (s)"
    )
    max_interval: float = Field(
        default=30.0, gt=0, description="Maximum adaptive sampling interval (s)"
    )
    enabled_monitors: list[str] = Field(
        default_factory=lambda: ["network", "process", "event_log"],
        description="List of monitor types to activate",
    )
    performance_interval: float = Field(
        default=5.0, gt=0, description="Per-process perf sampling interval (s)"
    )
    bandwidth_interval: float = Field(
        default=5.0, gt=0, description="Bandwidth sampling interval (s)"
    )
    latency_interval: float = Field(
        default=10.0, gt=0, description="Latency probe interval (s)"
    )
    latency_targets: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1"],
        description="Hosts to ping for latency measurement",
    )
    performance_cpu_threshold: float = Field(
        default=80.0, ge=0, le=100, description="CPU alert threshold (%)"
    )
    performance_io_threshold_mbps: float = Field(
        default=100.0, gt=0, description="IO alert threshold (MB/s)"
    )
    latency_jitter_threshold_ms: float = Field(
        default=50.0, gt=0, description="Jitter alert threshold (ms)"
    )
    bandwidth_drop_threshold_pct: float = Field(
        default=50.0, gt=0, le=100, description="Bandwidth drop alert threshold (%)"
    )
    event_log: EventLogConfig = Field(default_factory=EventLogConfig)

    @field_validator("max_interval")
    @classmethod
    def max_gte_min(cls, v: float, info: Any) -> float:
        min_val = info.data.get("min_interval")
        if min_val is not None and v < min_val:
            msg = f"max_interval ({v}) must be >= min_interval ({min_val})"
            raise ValueError(msg)
        return v


class StorageConfig(BaseModel):
    """Database / storage settings."""

    db_path: str = Field(default="data/guai.db", description="SQLite database path")
    retention_days: int = Field(default=30, gt=0, description="Data retention period in days")
    batch_size: int = Field(default=50, gt=0, description="Batch insert size")


class EventBusConfig(BaseModel):
    """Internal event bus settings."""

    max_queue_size: int = Field(default=10000, gt=0, description="Max events in queue")
    drop_strategy: Literal["oldest", "newest", "none"] = Field(
        default="oldest",
        description="Strategy when queue is full",
    )


class AlertsConfig(BaseModel):
    """Alert deduplication and channel settings."""

    suppress_window_minutes: int = Field(
        default=15, ge=0, description="Alert suppression window (minutes)"
    )
    max_alerts_per_minute: int = Field(
        default=100, gt=0, description="Rate limit for alerts per minute"
    )
    enabled_channels: list[str] = Field(
        default_factory=lambda: ["cli"],
        description="Enabled alert output channels",
    )


class RulesConfig(BaseModel):
    """Detection rules settings."""

    rules_dir: str = Field(default="config/rules", description="Directory containing rule files")


class GuAIConfig(BaseSettings):
    """Root configuration for GuAI system.

    Can be loaded from a TOML file via ``GuAIConfig.from_toml(path)``.
    """

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    event_bus: EventBusConfig = Field(default_factory=EventBusConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)

    @classmethod
    def from_toml(cls, path: str | Path) -> GuAIConfig:
        """Load configuration from a TOML file.

        Args:
            path: Path to the TOML configuration file.

        Returns:
            A validated ``GuAIConfig`` instance.

        Raises:
            ConfigError: If the file cannot be read or parsed, or validation fails.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise ConfigError(f"Config file not found: {filepath}")

        try:
            with filepath.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"Invalid TOML in {filepath}: {exc}") from exc

        try:
            return cls.model_validate(data)
        except Exception as exc:
            raise ConfigError(f"Config validation error: {exc}") from exc
