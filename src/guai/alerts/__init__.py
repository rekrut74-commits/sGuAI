"""GuAI Alert System — alert management, deduplication, and delivery."""

from guai.alerts.channels import AlertChannel, CLIChannel
from guai.alerts.dedup import AlertDeduplicator
from guai.alerts.manager import AlertManager

__all__ = ["AlertManager", "AlertChannel", "CLIChannel", "AlertDeduplicator"]
