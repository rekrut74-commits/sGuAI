"""Tests for the rule engine, matcher, and detection rule models."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from guai.core.models import SecurityEvent
from guai.core.types import Severity
from guai.rules.engine import RuleEngine
from guai.rules.matcher import RuleMatcher
from guai.rules.models import DetectionRule, RuleMatch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def matcher() -> RuleMatcher:
    return RuleMatcher()


@pytest.fixture
def engine() -> RuleEngine:
    return RuleEngine()


@pytest.fixture
def instant_rule() -> DetectionRule:
    """A simple instant rule (no window, threshold=1)."""
    return DetectionRule(
        name="log_clearing",
        description="Log cleared",
        severity=Severity.CRITICAL,
        source="event_log",
        conditions={"category": "security", "data.event_id": 1102},
        window_seconds=0,
        threshold=1,
        mitre_technique="T1070.001",
    )


@pytest.fixture
def threshold_rule() -> DetectionRule:
    """A threshold rule requiring 5 matches in 60s."""
    return DetectionRule(
        name="brute_force",
        description="Brute force detected",
        severity=Severity.HIGH,
        source="event_log",
        conditions={"category": "auth", "data.event_id": 4625},
        window_seconds=60,
        threshold=5,
        mitre_technique="T1110.001",
    )


def _make_event(
    category: str = "auth",
    data: dict | None = None,
    severity: Severity = Severity.MEDIUM,
    source: str = "event_log",
) -> SecurityEvent:
    """Helper to create a SecurityEvent quickly."""
    return SecurityEvent.create(
        source=source,
        severity=severity,
        category=category,
        data=data or {},
    )


# ---------------------------------------------------------------------------
# RuleEngine tests
# ---------------------------------------------------------------------------


class TestRuleEngineLoadRules:
    def test_load_rules_from_directory(self, tmp_path: Path) -> None:
        """Load multiple YAML rule files from a directory."""
        rule1 = {
            "name": "rule_one",
            "description": "First rule",
            "severity": 2,
            "source": "event_log",
            "conditions": {"category": "auth"},
        }
        rule2 = {
            "name": "rule_two",
            "description": "Second rule",
            "severity": 3,
            "source": "network",
            "conditions": {"category": "network"},
        }
        (tmp_path / "rule1.yaml").write_text(yaml.dump(rule1), encoding="utf-8")
        (tmp_path / "rule2.yml").write_text(yaml.dump(rule2), encoding="utf-8")
        # Non-YAML file should be ignored
        (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")

        engine = RuleEngine()
        count = engine.load_rules(tmp_path)

        assert count == 2
        assert len(engine.rules) == 2
        names = {r.name for r in engine.rules}
        assert "rule_one" in names
        assert "rule_two" in names

    def test_load_rules_empty_directory(self, tmp_path: Path) -> None:
        """Loading from an empty directory returns 0."""
        engine = RuleEngine()
        assert engine.load_rules(tmp_path) == 0

    def test_load_rules_nonexistent_directory(self) -> None:
        """Loading from a nonexistent directory returns 0."""
        engine = RuleEngine()
        assert engine.load_rules("/nonexistent/path") == 0


class TestRuleEngineAddRule:
    def test_add_rule(self, engine: RuleEngine, instant_rule: DetectionRule) -> None:
        """Adding a rule makes it available in the rules list."""
        engine.add_rule(instant_rule)
        assert len(engine.rules) == 1
        assert engine.rules[0].name == "log_clearing"


class TestRuleEngineEvaluate:
    def test_evaluate_instant_rule(
        self, engine: RuleEngine, instant_rule: DetectionRule
    ) -> None:
        """An instant rule matches immediately on a single event."""
        engine.add_rule(instant_rule)
        event = _make_event(
            category="security",
            data={"event_id": 1102},
            severity=Severity.CRITICAL,
        )

        matches = engine.evaluate(event)

        assert len(matches) == 1
        assert matches[0].rule.name == "log_clearing"
        assert matches[0].count == 1
        assert len(matches[0].events) == 1

    def test_evaluate_threshold_rule(
        self, engine: RuleEngine, threshold_rule: DetectionRule
    ) -> None:
        """A threshold rule triggers only after 5 matching events within the window."""
        engine.add_rule(threshold_rule)

        # First 4 events should NOT trigger
        for _ in range(4):
            event = _make_event(category="auth", data={"event_id": 4625})
            matches = engine.evaluate(event)
            assert len(matches) == 0

        # 5th event should trigger
        event = _make_event(category="auth", data={"event_id": 4625})
        matches = engine.evaluate(event)

        assert len(matches) == 1
        assert matches[0].rule.name == "brute_force"
        assert matches[0].count == 5

    def test_threshold_not_reached(
        self, engine: RuleEngine, threshold_rule: DetectionRule
    ) -> None:
        """4 events with threshold=5 should NOT trigger the rule."""
        engine.add_rule(threshold_rule)

        for _ in range(4):
            event = _make_event(category="auth", data={"event_id": 4625})
            matches = engine.evaluate(event)

        assert len(matches) == 0

    def test_evaluate_no_match(self, engine: RuleEngine, instant_rule: DetectionRule) -> None:
        """An event that doesn't match conditions produces no matches."""
        engine.add_rule(instant_rule)
        event = _make_event(category="network", data={"event_id": 9999})

        matches = engine.evaluate(event)

        assert len(matches) == 0

    def test_evaluate_disabled_rule(self, engine: RuleEngine) -> None:
        """Disabled rules are not evaluated."""
        rule = DetectionRule(
            name="disabled_rule",
            description="Disabled",
            severity=Severity.LOW,
            source="event_log",
            conditions={"category": "auth"},
            enabled=False,
        )
        engine.add_rule(rule)
        event = _make_event(category="auth")

        matches = engine.evaluate(event)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# RuleMatcher tests
# ---------------------------------------------------------------------------


class TestRuleMatcherExact:
    def test_matcher_exact_match(self, matcher: RuleMatcher) -> None:
        """Exact value matching for top-level fields."""
        event = _make_event(category="auth", data={"event_id": 4625})
        assert matcher.matches(event, {"category": "auth"}) is True
        assert matcher.matches(event, {"category": "network"}) is False


class TestRuleMatcherNested:
    def test_matcher_nested_field(self, matcher: RuleMatcher) -> None:
        """Dot-notation resolves into the data dict."""
        event = _make_event(category="auth", data={"event_id": 4625})
        assert matcher.matches(event, {"data.event_id": 4625}) is True
        assert matcher.matches(event, {"data.event_id": 9999}) is False

    def test_matcher_deep_nested_field(self, matcher: RuleMatcher) -> None:
        """Dot-notation resolves deeply nested dicts."""
        event = _make_event(
            category="network",
            data={"connection": {"remote_ip": "10.0.0.1"}},
        )
        assert matcher.matches(event, {"data.connection.remote_ip": "10.0.0.1"}) is True

    def test_matcher_missing_nested_field(self, matcher: RuleMatcher) -> None:
        """Missing nested field returns no match."""
        event = _make_event(category="auth", data={})
        assert matcher.matches(event, {"data.event_id": 4625}) is False


class TestRuleMatcherOperators:
    def test_matcher_gte_operator(self, matcher: RuleMatcher) -> None:
        """Greater-than-or-equal operator."""
        event = _make_event(severity=Severity.HIGH)
        assert matcher.matches(event, {"severity": {"gte": 3}}) is True
        assert matcher.matches(event, {"severity": {"gte": 4}}) is False

    def test_matcher_gt_operator(self, matcher: RuleMatcher) -> None:
        """Greater-than operator."""
        event = _make_event(severity=Severity.HIGH)
        assert matcher.matches(event, {"severity": {"gt": 2}}) is True
        assert matcher.matches(event, {"severity": {"gt": 3}}) is False

    def test_matcher_lt_lte_operators(self, matcher: RuleMatcher) -> None:
        """Less-than and less-than-or-equal operators."""
        event = _make_event(severity=Severity.MEDIUM)
        assert matcher.matches(event, {"severity": {"lt": 3}}) is True
        assert matcher.matches(event, {"severity": {"lte": 2}}) is True
        assert matcher.matches(event, {"severity": {"lt": 2}}) is False

    def test_matcher_eq_operator(self, matcher: RuleMatcher) -> None:
        """Explicit eq operator."""
        event = _make_event(category="auth")
        assert matcher.matches(event, {"category": {"eq": "auth"}}) is True
        assert matcher.matches(event, {"category": {"eq": "network"}}) is False

    def test_matcher_contains_operator(self, matcher: RuleMatcher) -> None:
        """Substring contains operator."""
        event = _make_event(category="authentication")
        assert matcher.matches(event, {"category": {"contains": "auth"}}) is True
        assert matcher.matches(event, {"category": {"contains": "xyz"}}) is False

    def test_matcher_regex_operator(self, matcher: RuleMatcher) -> None:
        """Regex matching operator."""
        event = _make_event(category="auth_failure")
        assert matcher.matches(event, {"category": {"regex": r"^auth_\w+"}}) is True
        assert matcher.matches(event, {"category": {"regex": r"^network"}}) is False

    def test_matcher_in_operator(self, matcher: RuleMatcher) -> None:
        """Value-in-list operator."""
        event = _make_event(category="auth")
        assert matcher.matches(event, {"category": {"in": ["auth", "security"]}}) is True
        assert matcher.matches(event, {"category": {"in": ["network", "file"]}}) is False

    def test_matcher_combined_operators(self, matcher: RuleMatcher) -> None:
        """Multiple operators in a single condition dict (AND logic)."""
        event = _make_event(severity=Severity.HIGH)
        assert matcher.matches(event, {"severity": {"gte": 2, "lte": 4}}) is True
        assert matcher.matches(event, {"severity": {"gte": 4, "lte": 4}}) is False


# ---------------------------------------------------------------------------
# DetectionRule.from_yaml / from_dict tests
# ---------------------------------------------------------------------------


class TestDetectionRuleYaml:
    def test_rule_from_yaml(self, tmp_path: Path) -> None:
        """Load a rule from a YAML file."""
        rule_data = {
            "name": "test_rule",
            "description": "A test rule",
            "severity": 3,
            "source": "event_log",
            "conditions": {"category": "auth", "data.event_id": 4625},
            "window_seconds": 60,
            "threshold": 5,
            "mitre_technique": "T1110.001",
        }
        rule_file = tmp_path / "test_rule.yaml"
        rule_file.write_text(yaml.dump(rule_data), encoding="utf-8")

        rule = DetectionRule.from_yaml(rule_file)

        assert rule.name == "test_rule"
        assert rule.severity == Severity.HIGH
        assert rule.source == "event_log"
        assert rule.conditions == {"category": "auth", "data.event_id": 4625}
        assert rule.window_seconds == 60
        assert rule.threshold == 5
        assert rule.mitre_technique == "T1110.001"
        assert rule.enabled is True

    def test_rule_from_dict(self) -> None:
        """Create a rule from a dictionary."""
        data = {
            "name": "dict_rule",
            "description": "From dict",
            "severity": 2,
            "source": "network",
            "conditions": {"category": "network"},
        }
        rule = DetectionRule.from_dict(data)
        assert rule.name == "dict_rule"
        assert rule.severity == Severity.MEDIUM
        assert rule.window_seconds == 0
        assert rule.threshold == 1
        assert rule.enabled is True

    def test_rule_from_dict_with_enabled_false(self) -> None:
        """Enabled can be set to False via dict."""
        data = {
            "name": "disabled",
            "description": "Disabled rule",
            "severity": 1,
            "source": "process",
            "conditions": {},
            "enabled": False,
        }
        rule = DetectionRule.from_dict(data)
        assert rule.enabled is False
