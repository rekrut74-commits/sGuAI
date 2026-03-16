"""GuAI core module — types, configuration, logging, and exceptions."""

from guai.core.config import (
    AlertsConfig,
    EventBusConfig,
    EventLogConfig,
    GeneralConfig,
    GuAIConfig,
    MonitoringConfig,
    RulesConfig,
    StorageConfig,
)
from guai.core.exceptions import (
    AlertError,
    ConfigError,
    EventBusError,
    GuAIError,
    MonitorError,
    RuleEngineError,
    StorageError,
)
from guai.core.logging_setup import SensitiveFieldRedactor, setup_logging
from guai.core.types import (
    AlertStatus,
    ModuleHealth,
    MonitorType,
    Severity,
    TrustLevel,
)

__all__ = [
    # Types / enums
    "AlertStatus",
    "ModuleHealth",
    "MonitorType",
    "Severity",
    "TrustLevel",
    # Configuration
    "AlertsConfig",
    "EventBusConfig",
    "EventLogConfig",
    "GeneralConfig",
    "GuAIConfig",
    "MonitoringConfig",
    "RulesConfig",
    "StorageConfig",
    # Exceptions
    "AlertError",
    "ConfigError",
    "EventBusError",
    "GuAIError",
    "MonitorError",
    "RuleEngineError",
    "StorageError",
    # Logging
    "SensitiveFieldRedactor",
    "setup_logging",
]
