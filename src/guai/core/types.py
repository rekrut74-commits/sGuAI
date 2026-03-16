"""Core type definitions for GuAI system."""

from enum import Enum, IntEnum


class Severity(IntEnum):
    """Severity level for alerts and events."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TrustLevel(Enum):
    """Trust level classification for processes and network connections."""

    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi_trusted"
    TRUSTED = "trusted"


class MonitorType(Enum):
    """Types of monitors available in the system."""

    NETWORK = "network"
    PROCESS = "process"
    EVENT_LOG = "event_log"
    FILE = "file"
    ETW = "etw"
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    DNS = "dns"
    PERFORMANCE = "performance"
    BANDWIDTH = "bandwidth"
    LATENCY = "latency"


class AlertStatus(Enum):
    """Lifecycle status of an alert."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class ModuleHealth(Enum):
    """Health status of a system module."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STOPPED = "stopped"
