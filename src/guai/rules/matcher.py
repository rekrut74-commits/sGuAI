"""Rule matcher — evaluates SecurityEvents against rule conditions."""

from __future__ import annotations

import re
from typing import Any

from guai.core.models import SecurityEvent


class RuleMatcher:
    """Matches SecurityEvents against rule conditions.

    Supports dot-notation for nested data fields and various comparison operators.
    """

    def matches(self, event: SecurityEvent, conditions: dict[str, Any]) -> bool:
        """Check if event matches all conditions.

        Supports dot-notation for nested data fields:
        - "category": "auth"          -> event.category == "auth"
        - "data.event_id": 4625       -> event.data["event_id"] == 4625
        - "severity": {"gte": 3}      -> event.severity >= 3

        Operators in dict values:
        - {"eq": value}               -> exact match (default if bare value)
        - {"contains": str}           -> substring match
        - {"regex": pattern}          -> regex match
        - {"gt": num}, {"gte": num}, {"lt": num}, {"lte": num}
        - {"in": list}                -> value in list

        Args:
            event: The security event to evaluate.
            conditions: Dictionary of field conditions.

        Returns:
            True if all conditions match.
        """
        for field_path, expected in conditions.items():
            actual = self._resolve_field(event, field_path)
            if actual is _MISSING:
                return False
            if not self._check_condition(actual, expected):
                return False
        return True

    def _resolve_field(self, event: SecurityEvent, field_path: str) -> Any:
        """Resolve a dot-notation field path on a SecurityEvent.

        Top-level attributes are resolved first (category, severity, source, etc.).
        Dot-notation paths like "data.event_id" resolve into nested data dict.

        Args:
            event: The event to read from.
            field_path: Dot-separated field path.

        Returns:
            The resolved value, or _MISSING sentinel if not found.
        """
        parts = field_path.split(".")

        # Start with the first part — try event attribute
        first = parts[0]
        if hasattr(event, first):
            value = getattr(event, first)
        else:
            return _MISSING

        # Navigate remaining parts through nested dicts
        for part in parts[1:]:
            if isinstance(value, dict):
                if part in value:
                    value = value[part]
                else:
                    return _MISSING
            else:
                return _MISSING

        return value

    def _check_condition(self, actual: Any, expected: Any) -> bool:
        """Check a single condition against an actual value.

        If expected is a dict, treat keys as operators. Otherwise do equality check.

        Args:
            actual: The value from the event.
            expected: The expected value or operator dict.

        Returns:
            True if the condition is satisfied.
        """
        if isinstance(expected, dict):
            return self._check_operators(actual, expected)
        # Bare value — exact match
        return actual == expected

    def _check_operators(self, actual: Any, operators: dict[str, Any]) -> bool:
        """Evaluate operator-based conditions.

        Args:
            actual: The value from the event.
            operators: Dict of operator -> operand pairs.

        Returns:
            True if ALL operators match.
        """
        for op, operand in operators.items():
            if op == "eq":
                if actual != operand:
                    return False
            elif op == "gt":
                if not (actual > operand):
                    return False
            elif op == "gte":
                if not (actual >= operand):
                    return False
            elif op == "lt":
                if not (actual < operand):
                    return False
            elif op == "lte":
                if not (actual <= operand):
                    return False
            elif op == "contains":
                if not isinstance(actual, str) or operand not in actual:
                    return False
            elif op == "regex":
                if not isinstance(actual, str) or not re.search(operand, actual):
                    return False
            elif op == "in":
                if actual not in operand:
                    return False
            else:
                # Unknown operator — treat as nested dict key (conditions dict in YAML)
                # This shouldn't normally happen; fail safe
                return False
        return True


class _MissingSentinel:
    """Sentinel for missing field values."""

    def __repr__(self) -> str:
        return "<MISSING>"

    def __bool__(self) -> bool:
        return False


_MISSING = _MissingSentinel()
