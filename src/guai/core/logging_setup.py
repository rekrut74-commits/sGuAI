"""Structured logging setup for GuAI system.

Provides structured logging via structlog with sensitive field redaction.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog


# Fields whose values should be redacted in log output.
_SENSITIVE_PATTERNS: re.Pattern[str] = re.compile(
    r"(password|token|key|secret|auth|credential|api_key)",
    re.IGNORECASE,
)

_REDACTED = "***REDACTED***"


class SensitiveFieldRedactor:
    """structlog processor that masks values for sensitive field names.

    Any event-dict key matching one of the sensitive patterns will have its
    value replaced with ``***REDACTED***``.
    """

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: dict[str, Any],
    ) -> dict[str, Any]:
        for field_name in list(event_dict.keys()):
            if _SENSITIVE_PATTERNS.search(field_name):
                event_dict[field_name] = _REDACTED
        return event_dict


def setup_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure structlog and stdlib logging for the application.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_output: If ``True``, render logs as JSON (production).
                     If ``False``, use colored console output (development).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure stdlib root logger so that structlog's PrintLogger output
    # and any third-party library logs are captured consistently.
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        force=True,
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        SensitiveFieldRedactor(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Also install a formatter on the root handler so stdlib logs get
    # the same processing pipeline.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
