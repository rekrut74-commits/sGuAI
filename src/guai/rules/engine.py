"""Rule engine — loads detection rules and evaluates security events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from guai.core.models import SecurityEvent
from guai.rules.matcher import RuleMatcher
from guai.rules.models import DetectionRule, RuleMatch


class RuleEngine:
    """Loads rules from YAML directory and evaluates events against them.

    Supports both instant rules (threshold=1, window=0) and threshold-based
    rules that require N matches within a time window to trigger.
    """

    def __init__(self) -> None:
        self._rules: list[DetectionRule] = []
        self._matcher = RuleMatcher()
        # rule_name -> list of (timestamp, event) in current window
        self._window_events: dict[str, list[tuple[datetime, SecurityEvent]]] = {}

    def load_rules(self, rules_dir: str | Path) -> int:
        """Load all .yaml/.yml files from a directory.

        Args:
            rules_dir: Path to the directory containing rule YAML files.

        Returns:
            Number of rules successfully loaded.
        """
        rules_dir = Path(rules_dir)
        count = 0
        if not rules_dir.is_dir():
            return 0

        for rule_file in sorted(rules_dir.iterdir()):
            if rule_file.suffix in (".yaml", ".yml"):
                try:
                    rule = DetectionRule.from_yaml(rule_file)
                    self._rules.append(rule)
                    count += 1
                except Exception:
                    # Skip malformed rule files
                    continue
        return count

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a single rule to the engine.

        Args:
            rule: The detection rule to add.
        """
        self._rules.append(rule)

    def evaluate(self, event: SecurityEvent) -> list[RuleMatch]:
        """Evaluate an event against all enabled rules.

        For instant rules (window_seconds=0 or threshold=1 with no window):
            Returns a match immediately if conditions are satisfied.

        For threshold rules:
            Tracks matching events in a time window. Only triggers when
            the threshold count is reached within the window.
            Expired events are cleaned up automatically.

        Args:
            event: The security event to evaluate.

        Returns:
            List of RuleMatch objects for all triggered rules.
        """
        matches: list[RuleMatch] = []
        now = datetime.now(tz=timezone.utc)

        for rule in self._rules:
            if not rule.enabled:
                continue

            if not self._matcher.matches(event, rule.conditions):
                continue

            # Instant rule — no window tracking needed
            if rule.window_seconds == 0 or rule.threshold <= 1:
                match = RuleMatch(
                    rule=rule,
                    events=[event],
                    matched_at=now,
                    count=1,
                )
                matches.append(match)
                continue

            # Threshold rule — track events in window
            if rule.name not in self._window_events:
                self._window_events[rule.name] = []

            window = self._window_events[rule.name]
            window.append((now, event))

            # Clean up expired events
            cutoff = now.timestamp() - rule.window_seconds
            window[:] = [
                (ts, ev) for ts, ev in window if ts.timestamp() >= cutoff
            ]

            # Check if threshold is reached
            if len(window) >= rule.threshold:
                match = RuleMatch(
                    rule=rule,
                    events=[ev for _, ev in window],
                    matched_at=now,
                    count=len(window),
                )
                matches.append(match)
                # Clear window after match to avoid re-triggering on same events
                window.clear()

        return matches

    @property
    def rules(self) -> list[DetectionRule]:
        """Return the list of loaded rules."""
        return list(self._rules)
