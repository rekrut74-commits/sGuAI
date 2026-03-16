"""Main orchestrator — wires all GuAI modules together."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from guai.alerts.channels import AlertChannel, CLIChannel
from guai.alerts.dedup import AlertDeduplicator
from guai.alerts.manager import AlertManager
from guai.core.config import GuAIConfig
from guai.core.event_bus import EventBus
from guai.core.logging_setup import setup_logging
from guai.core.models import Alert, SecurityEvent
from guai.core.scheduler import Scheduler
from guai.core.types import ModuleHealth
from guai.monitors.base import BaseMonitor
from guai.monitors.event_log import EventLogMonitor
from guai.monitors.network import NetworkMonitor
from guai.monitors.process import ProcessMonitor
from guai.rules.engine import RuleEngine
from guai.rules.models import RuleMatch
from guai.storage.alert_store import AlertStore
from guai.storage.database import Database
from guai.storage.event_store import EventStore

logger = logging.getLogger(__name__)


class GuAIApp:
    """Main orchestrator. Wires all modules together.

    Lifecycle:
        1. ``__init__`` — stores config
        2. ``initialize()`` — creates all modules in correct order
        3. ``start()`` — runs event bus, monitors, scheduler
        4. ``stop()`` — graceful shutdown in reverse order
    """

    def __init__(self, config: GuAIConfig) -> None:
        self.config = config
        self.event_bus: EventBus
        self.database: Database
        self.event_store: EventStore
        self.alert_store: AlertStore
        self.rule_engine: RuleEngine
        self.alert_manager: AlertManager
        self.monitors: list[BaseMonitor] = []
        self.scheduler: Scheduler
        self._running = False
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all modules in correct order.

        1. Logging
        2. Database + stores
        3. EventBus
        4. Rule engine (load rules)
        5. Alert manager
        6. Monitors
        7. Wire event_bus subscriber for rule evaluation
        8. Scheduler for periodic tasks
        """
        # 1. Logging
        setup_logging(level=self.config.general.log_level)

        # 2. Database + stores
        db_path = Path(self.config.storage.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.database = Database(db_path)
        await self.database.initialize()
        self.event_store = EventStore(self.database)
        self.alert_store = AlertStore(self.database)

        # 3. EventBus
        self.event_bus = EventBus(
            max_queue_size=self.config.event_bus.max_queue_size,
            drop_strategy=self.config.event_bus.drop_strategy,
        )

        # 4. Rule engine
        self.rule_engine = RuleEngine()
        rules_dir = Path(self.config.rules.rules_dir)
        if rules_dir.is_dir():
            count = self.rule_engine.load_rules(rules_dir)
            logger.info("Loaded %d detection rules from %s", count, rules_dir)
        else:
            logger.info("Rules directory %s not found, starting with no rules", rules_dir)

        # 5. Alert manager
        channels: list[AlertChannel] = []
        for ch_name in self.config.alerts.enabled_channels:
            if ch_name == "cli":
                channels.append(CLIChannel())
        dedup = AlertDeduplicator(
            suppress_window_minutes=self.config.alerts.suppress_window_minutes,
        )
        self.alert_manager = AlertManager(channels=channels, dedup=dedup)

        # 6. Monitors
        self.monitors = []
        enabled = self.config.monitoring.enabled_monitors
        if "network" in enabled:
            self.monitors.append(NetworkMonitor(self.event_bus, self.config))
        if "process" in enabled:
            self.monitors.append(ProcessMonitor(self.event_bus, self.config))
        if "event_log" in enabled:
            self.monitors.append(EventLogMonitor(self.event_bus, self.config))
        if "wifi" in enabled:
            from guai.monitors.wifi import WiFiMonitor

            self.monitors.append(WiFiMonitor(self.event_bus, self.config))
        if "bluetooth" in enabled:
            from guai.monitors.bluetooth import BluetoothMonitor

            self.monitors.append(BluetoothMonitor(self.event_bus, self.config))
        if "dns" in enabled:
            from guai.monitors.dns import DNSMonitor

            self.monitors.append(DNSMonitor(self.event_bus, self.config))
        if "performance" in enabled:
            from guai.monitors.performance import PerformanceMonitor

            self.monitors.append(PerformanceMonitor(self.event_bus, self.config))
        if "bandwidth" in enabled:
            from guai.monitors.bandwidth import BandwidthMonitor

            self.monitors.append(BandwidthMonitor(self.event_bus, self.config))
        if "latency" in enabled:
            from guai.monitors.latency import LatencyMonitor

            self.monitors.append(LatencyMonitor(self.event_bus, self.config))

        # 7. Wire subscriber
        self.event_bus.subscribe(self._on_event)

        # 8. Scheduler
        self.scheduler = Scheduler()
        self.scheduler.schedule(
            "dedup_cleanup",
            self._dedup_cleanup,
            interval=60.0,
        )
        self.scheduler.schedule(
            "storage_stats",
            self._log_stats,
            interval=300.0,
        )

        self._initialized = True
        logger.info("GuAI application initialized")

    async def start(self) -> None:
        """Start all modules using asyncio tasks.

        Tasks:
        - EventBus dispatch loop
        - Each monitor's start()
        - Scheduler for periodic tasks
        """
        if self._running:
            return
        if not self._initialized:
            await self.initialize()

        self._running = True

        # Start event bus dispatch loop
        await self.event_bus.start()

        # Start scheduler
        await self.scheduler.start()

        # Start each monitor
        for monitor in self.monitors:
            await monitor.start()

        logger.info(
            "GuAI started: %d monitors, %d rules",
            len(self.monitors),
            len(self.rule_engine.rules),
        )

    async def stop(self) -> None:
        """Graceful shutdown in reverse order."""
        if not self._running:
            return

        self._running = False
        logger.info("GuAI shutting down...")

        # 1. Stop monitors
        for monitor in reversed(self.monitors):
            try:
                await monitor.stop()
            except Exception:
                logger.exception("Error stopping monitor %s", monitor.monitor_type.value)

        # 2. Stop scheduler
        try:
            await self.scheduler.stop()
        except Exception:
            logger.exception("Error stopping scheduler")

        # 3. Stop event bus (drains remaining events)
        try:
            await self.event_bus.stop()
        except Exception:
            logger.exception("Error stopping event bus")

        # 4. Close database
        try:
            await self.database.close()
        except Exception:
            logger.exception("Error closing database")

        logger.info("GuAI stopped")

    async def health_check(self) -> dict[str, ModuleHealth]:
        """Return health of all modules.

        Returns:
            Dictionary mapping module name to its ModuleHealth status.
        """
        health: dict[str, ModuleHealth] = {}

        # Event bus
        if hasattr(self, "event_bus") and self.event_bus._running:
            health["event_bus"] = ModuleHealth.HEALTHY
        else:
            health["event_bus"] = ModuleHealth.STOPPED

        # Database
        if hasattr(self, "database") and self.database._connection is not None:
            health["database"] = ModuleHealth.HEALTHY
        else:
            health["database"] = ModuleHealth.STOPPED

        # Monitors
        for monitor in self.monitors:
            name = f"monitor_{monitor.monitor_type.value}"
            health[name] = monitor.health

        # Rule engine
        if hasattr(self, "rule_engine"):
            health["rule_engine"] = ModuleHealth.HEALTHY
        else:
            health["rule_engine"] = ModuleHealth.STOPPED

        # Alert manager
        if hasattr(self, "alert_manager"):
            health["alert_manager"] = ModuleHealth.HEALTHY
        else:
            health["alert_manager"] = ModuleHealth.STOPPED

        return health

    async def _on_event(self, event: SecurityEvent) -> None:
        """Event handler: evaluate rules, create alerts, store event.

        Args:
            event: Incoming security event from the bus.
        """
        # Store event
        try:
            await self.event_store.store(
                event_id=event.event_id,
                timestamp=event.timestamp.isoformat(),
                source=event.source,
                severity=int(event.severity),
                category=event.category,
                data=json.dumps(event.data),
                trust_level=event.trust_level.value,
                mitre_technique=event.mitre_technique,
            )
        except Exception:
            logger.exception("Failed to store event %s", event.event_id)

        # Evaluate rules
        matches: list[RuleMatch] = self.rule_engine.evaluate(event)
        if not matches:
            return

        # Process matches -> create alerts
        try:
            alerts: list[Alert] = await self.alert_manager.process_matches(matches)
            # Store alerts
            for alert in alerts:
                await self.alert_store.create(
                    alert_id=alert.alert_id,
                    timestamp=alert.timestamp.isoformat(),
                    severity=int(alert.severity),
                    title=alert.title,
                    description=alert.description,
                    source_events=json.dumps(alert.source_events),
                    status=alert.status.value,
                    mitre_technique=alert.mitre_technique,
                    rule_name=alert.rule_name,
                )
        except Exception:
            logger.exception("Error processing rule matches for event %s", event.event_id)

    async def _dedup_cleanup(self) -> None:
        """Periodic task: clean up expired dedup entries."""
        if hasattr(self, "alert_manager"):
            removed = self.alert_manager._dedup.cleanup()
            if removed > 0:
                logger.debug("Dedup cleanup: removed %d expired entries", removed)

    async def _log_stats(self) -> None:
        """Periodic task: log event bus and storage stats."""
        if hasattr(self, "event_bus"):
            stats = self.event_bus.stats
            logger.info(
                "EventBus stats: queue=%d, published=%d, dropped=%d, subscribers=%d",
                stats["queue_size"],
                stats["total_published"],
                stats["dropped_count"],
                stats["subscribers_count"],
            )
