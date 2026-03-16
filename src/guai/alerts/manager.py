"""Alert manager — orchestrates alert creation, dedup, and delivery."""

from __future__ import annotations

from guai.core.models import Alert
from guai.alerts.channels import AlertChannel
from guai.alerts.dedup import AlertDeduplicator
from guai.rules.models import RuleMatch


class AlertManager:
    """Manages the alert lifecycle: creation, deduplication, and delivery.

    Converts RuleMatch objects into Alert instances, applies deduplication,
    and sends alerts to all configured channels.
    """

    def __init__(
        self,
        channels: list[AlertChannel],
        dedup: AlertDeduplicator,
    ) -> None:
        self._channels = channels
        self._dedup = dedup
        self._alert_count: int = 0

    async def process_matches(self, matches: list[RuleMatch]) -> list[Alert]:
        """Convert rule matches to alerts, apply dedup, and send to channels.

        Args:
            matches: List of RuleMatch results from the rule engine.

        Returns:
            List of Alert objects that were actually sent (not suppressed).
        """
        alerts: list[Alert] = []

        for match in matches:
            rule = match.rule
            event_ids = [ev.event_id for ev in match.events]

            # Build dedup key from rule name and first event's key data
            key_data: dict[str, object] = {}
            if match.events:
                first = match.events[0]
                key_data = {"category": first.category, "source": first.source}

            fp = self._dedup.fingerprint(rule.name, key_data)
            if self._dedup.should_suppress(fp):
                continue

            alert = Alert.create(
                severity=rule.severity,
                title=rule.description,
                description=(
                    f"Rule '{rule.name}' triggered: {match.count} event(s) matched"
                ),
                source_events=event_ids,
                rule_name=rule.name,
                mitre_technique=rule.mitre_technique,
            )

            self._dedup.record(fp)
            await self.send_alert(alert)
            alerts.append(alert)
            self._alert_count += 1

        return alerts

    async def send_alert(self, alert: Alert) -> None:
        """Send an alert to all configured channels.

        Args:
            alert: The alert to deliver.
        """
        for channel in self._channels:
            try:
                await channel.send(alert)
            except Exception:
                # Don't let a single channel failure break the pipeline
                continue

    @property
    def alert_count(self) -> int:
        """Total number of alerts sent."""
        return self._alert_count
