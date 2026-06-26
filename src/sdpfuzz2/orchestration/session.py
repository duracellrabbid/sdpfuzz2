"""Session state and statistics for a fuzzing run."""

import time
from dataclasses import dataclass, field
from enum import StrEnum


class SessionState(StrEnum):
    """Lifecycle state of a fuzzing session."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


@dataclass
class FuzzSession:
    """Represents one fuzzing session configuration."""

    target_mac: str
    mode: str


@dataclass
class RunStatistics:
    """Tracks runtime statistics for a fuzzing session.

    All counters are monotonically increasing. ``elapsed_seconds`` is
    computed from the wall-clock start/stop times recorded internally.
    """

    packets_sent: int = 0
    packets_received: int = 0
    timeouts: int = 0
    errors: int = 0
    crashes_detected: int = 0

    _start_time: float = field(default=0.0, repr=False)
    _stop_time: float | None = field(default=None, repr=False)

    def start(self) -> None:
        """Record the start time."""
        self._start_time = time.monotonic()
        self._stop_time = None

    def stop(self) -> None:
        """Record the stop time."""
        self._stop_time = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since start (or total if stopped)."""
        if self._start_time == 0.0:
            return 0.0
        end = self._stop_time if self._stop_time is not None else time.monotonic()
        return end - self._start_time
