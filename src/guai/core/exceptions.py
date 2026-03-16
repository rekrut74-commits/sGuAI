"""Exception hierarchy for GuAI system."""


class GuAIError(Exception):
    """Base exception for all GuAI errors."""

    def __init__(self, message: str = "", *, detail: str | None = None) -> None:
        self.detail = detail
        super().__init__(message)


class ConfigError(GuAIError):
    """Raised when configuration is invalid or cannot be loaded."""


class StorageError(GuAIError):
    """Raised when a storage operation fails (database read/write, retention, etc.)."""


class MonitorError(GuAIError):
    """Raised when a monitor encounters an unrecoverable error."""


class EventBusError(GuAIError):
    """Raised when the event bus encounters an error (queue full, dispatch failure)."""


class RuleEngineError(GuAIError):
    """Raised when rule evaluation or loading fails."""


class AlertError(GuAIError):
    """Raised when alert creation, dispatch or channel communication fails."""
