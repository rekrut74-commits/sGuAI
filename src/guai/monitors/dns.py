"""DNS cache monitor for GuAI.

Reads the local DNS resolver cache using ``ipconfig /displaydns`` on Windows.
Falls back gracefully on non-Windows platforms.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import subprocess
from collections import Counter
from collections.abc import AsyncIterator
from typing import Any

from guai.core.models import SecurityEvent
from guai.core.types import ModuleHealth, MonitorType, Severity
from guai.monitors.base import BaseMonitor

logger = logging.getLogger(__name__)


class DNSMonitor(BaseMonitor):
    """Monitors DNS resolver cache for new or suspicious entries.

    Uses ``ipconfig /displaydns`` which does not require admin privileges.
    Detects DGA-like domains (high entropy, long labels) and emits events
    for newly resolved domains.
    """

    # Thresholds for suspicious domain detection
    _MAX_DOMAIN_LENGTH = 50
    _MIN_ENTROPY_SUSPICIOUS = 3.5
    _MIN_ENTROPY_SHORT = 3.2  # stricter for short random-looking labels

    def __init__(self, event_bus: Any, config: Any) -> None:
        super().__init__(event_bus, config)
        self._interval: float = getattr(
            getattr(config, "monitoring", None), "dns_interval", 10.0
        )
        self._known_domains: set[str] = set()
        self._available = True

    @property
    def monitor_type(self) -> MonitorType:
        return MonitorType.DNS

    async def stream(self) -> AsyncIterator[SecurityEvent]:
        """Yield events for DNS cache changes."""
        # Probe once
        try:
            test = await asyncio.to_thread(self._run_ipconfig)
            if test is None:
                self._available = False
                self._health = ModuleHealth.DEGRADED
                logger.warning("DNSMonitor inactive: ipconfig /displaydns not available")
                return
        except Exception:
            self._available = False
            self._health = ModuleHealth.DEGRADED
            logger.warning("DNSMonitor inactive: failed initial probe")
            return

        while self._running:
            try:
                output = await asyncio.to_thread(self._run_ipconfig)
                if output is None:
                    await asyncio.sleep(self._interval)
                    continue

                records = self._parse_dns_cache(output)
                current_domains = {r["domain"] for r in records}

                # New domains
                for rec in records:
                    if rec["domain"] not in self._known_domains:
                        severity = Severity.LOW
                        event_type = "new_dns_record"

                        if self._is_suspicious(rec["domain"]):
                            severity = Severity.MEDIUM
                            event_type = "suspicious_domain"

                        yield SecurityEvent.create(
                            source="dns_monitor",
                            severity=severity,
                            category="dns",
                            data={
                                "event_type": event_type,
                                "domain": rec["domain"],
                                "record_type": rec["record_type"],
                                "data": rec["data"],
                                "ttl": rec["ttl"],
                            },
                        )

                self._known_domains = current_domains

            except Exception:
                logger.exception("Error reading DNS cache")

            await asyncio.sleep(self._interval)

    @staticmethod
    def _run_ipconfig() -> str | None:
        """Run ipconfig /displaydns and return stdout, or None on failure."""
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return None
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _parse_dns_cache(output: str) -> list[dict[str, str]]:
        """Parse ipconfig /displaydns output into record dicts."""
        records: list[dict[str, str]] = []
        current_domain = ""
        current_record: dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()

            # Record Name line
            m = re.match(r"Record Name\s*[\.\s]*:\s*(.*)", line)
            if m:
                if current_record.get("domain"):
                    records.append(current_record)
                current_domain = m.group(1).strip().rstrip(".")
                current_record = {
                    "domain": current_domain,
                    "record_type": "",
                    "data": "",
                    "ttl": "",
                }
                continue

            m = re.match(r"Record Type\s*[\.\s]*:\s*(.*)", line)
            if m:
                raw = m.group(1).strip()
                current_record["record_type"] = _record_type_name(raw)
                continue

            m = re.match(r"Time To Live\s*[\.\s]*:\s*(.*)", line)
            if m:
                current_record["ttl"] = m.group(1).strip()
                continue

            m = re.match(r"(?:Data Length|Section)\s*[\.\s]*:\s*(.*)", line)
            if m:
                continue

            # A (Host) Record / AAAA Record / CNAME Record data line
            m = re.match(r"(?:A \(Host\)|AAAA|CNAME)\s+Record\s*[\.\s]*:\s*(.*)", line)
            if m:
                current_record["data"] = m.group(1).strip()
                continue

        if current_record.get("domain"):
            records.append(current_record)

        return records

    @classmethod
    def _is_suspicious(cls, domain: str) -> bool:
        """Check if a domain looks DGA-generated or tunnel-like."""
        # Skip common TLDs and short domains
        if len(domain) < 10:
            return False

        # Long domain names
        if len(domain) > cls._MAX_DOMAIN_LENGTH:
            return True

        # High entropy in longest label
        labels = domain.split(".")
        # Filter out TLD and SLD
        if len(labels) > 2:
            host_part = ".".join(labels[:-2])
        else:
            host_part = labels[0]

        entropy = _shannon_entropy(host_part)

        # Long labels with high entropy (tunnel-like)
        if len(host_part) > 20 and entropy > cls._MIN_ENTROPY_SUSPICIOUS:
            return True

        # Short but clearly random labels (DGA-like: "njtzzrvg0lwj3bsn")
        if 10 <= len(host_part) <= 20 and entropy > cls._MIN_ENTROPY_SHORT:
            # Check consonant-to-vowel ratio on alpha chars only
            # (ignore digits/dots — CDN hashes like "e83157.dscb" have few
            # alpha chars but normal vowel distribution)
            alpha = [c for c in host_part.lower() if c.isalpha()]
            if len(alpha) >= 8:
                vowels = sum(1 for c in alpha if c in "aeiou")
                ratio = vowels / len(alpha)
                if ratio < 0.15:  # natural English ~40%, DGA typically <10%
                    return True

        return False


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _record_type_name(raw: str) -> str:
    """Convert numeric record type to name."""
    mapping = {"1": "A", "5": "CNAME", "28": "AAAA", "12": "PTR", "15": "MX", "2": "NS"}
    return mapping.get(raw, raw)
