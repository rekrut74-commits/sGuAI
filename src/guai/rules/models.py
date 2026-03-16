"""Detection rule and match models for the GuAI rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from guai.core.models import SecurityEvent
from guai.core.types import Severity


@dataclass
class DetectionRule:
    """A detection rule defining conditions to match against security events.

    Rules can be instant (window_seconds=0, threshold=1) or threshold-based
    (require N matches within a time window to trigger).
    """

    name: str
    description: str
    severity: Severity
    source: str  # e.g. "event_log", "network", "process"
    conditions: dict[str, Any]  # field conditions to match
    window_seconds: int = 0  # time window for threshold rules (0 = instant)
    threshold: int = 1  # how many matches in window to trigger
    mitre_technique: str | None = None
    enabled: bool = True

    @classmethod
    def from_yaml(cls, path: str | Path) -> DetectionRule:
        """Load a detection rule from a YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            A new DetectionRule instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            yaml.YAMLError: If the file is not valid YAML.
            KeyError: If required fields are missing.
        """
        path = Path(path)
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionRule:
        """Create a detection rule from a dictionary.

        Args:
            data: Dictionary with rule configuration.

        Returns:
            A new DetectionRule instance.

        Raises:
            KeyError: If required fields are missing.
        """
        return cls(
            name=data["name"],
            description=data["description"],
            severity=Severity(data["severity"]),
            source=data["source"],
            conditions=data["conditions"],
            window_seconds=data.get("window_seconds", 0),
            threshold=data.get("threshold", 1),
            mitre_technique=data.get("mitre_technique"),
            enabled=data.get("enabled", True),
        )


@dataclass
class RuleMatch:
    """Result of a successful rule match against one or more events.

    For instant rules, events will contain the single matching event.
    For threshold rules, events will contain all matching events within the window.
    """

    rule: DetectionRule
    events: list[SecurityEvent]  # matching events
    matched_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    count: int = 0  # how many matches in window

    def __post_init__(self) -> None:
        if self.count == 0:
            self.count = len(self.events)
