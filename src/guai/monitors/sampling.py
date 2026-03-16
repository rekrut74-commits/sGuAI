"""Adaptive sampling interval calculator for GuAI monitors."""

from __future__ import annotations


class AdaptiveSampler:
    """Dynamically adjusts sampling intervals based on anomaly scores.

    Higher anomaly scores cause shorter intervals (more frequent sampling).
    The interval is clamped between ``min_interval`` and ``max_interval``.

    For critical monitors the interval never exceeds ``critical_floor``,
    regardless of the current anomaly score.

    Args:
        base_interval: Default sampling interval in seconds.
        min_interval: Minimum interval (fastest sampling).
        max_interval: Maximum interval (slowest sampling).
        critical_floor: Ceiling interval for critical monitors.
    """

    def __init__(
        self,
        base_interval: float = 5.0,
        min_interval: float = 0.5,
        max_interval: float = 30.0,
        critical_floor: float = 1.0,
    ) -> None:
        self.base_interval = base_interval
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.critical_floor = critical_floor
        self._current_interval = base_interval

    def next_interval(self, anomaly_score: float = 0.0) -> float:
        """Calculate the next sampling interval.

        The anomaly_score is expected in the range [0.0, 1.0].
        A score of 0.0 returns ``base_interval``, while 1.0 returns
        ``min_interval``.  Values are linearly interpolated between
        these two extremes.

        Args:
            anomaly_score: Current anomaly score between 0.0 and 1.0.

        Returns:
            The next sampling interval in seconds.
        """
        # Clamp anomaly_score to [0, 1]
        score = max(0.0, min(1.0, anomaly_score))

        # Linear interpolation: high score -> low interval
        interval = self.base_interval - score * (self.base_interval - self.min_interval)

        # Clamp to [min_interval, max_interval]
        interval = max(self.min_interval, min(self.max_interval, interval))

        # Apply critical floor: never go above critical_floor
        interval = min(interval, self.critical_floor) if score >= 0.8 else interval

        self._current_interval = interval
        return interval

    def reset(self) -> None:
        """Reset to base interval."""
        self._current_interval = self.base_interval

    @property
    def current_interval(self) -> float:
        """Return the most recently calculated interval."""
        return self._current_interval
