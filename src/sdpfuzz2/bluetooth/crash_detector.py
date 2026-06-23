"""Crash detection and confidence scoring for Bluetooth device crashes.

Detects crashes using multiple signals: consecutive timeouts, connection state
changes, and HCI errors. Implements confidence scoring with worker corroboration.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class ErrorType(StrEnum):
    """Classification of errors encountered during fuzzing."""

    LOCAL_ADAPTER_ERROR = "local_adapter_error"  # HCI adapter issue, not target crash
    REMOTE_DEVICE_ERROR = "remote_device_error"  # Target device error
    CONNECTION_REFUSED = "connection_refused"  # Connection refused by target
    CONNECTION_RESET = "connection_reset"  # Connection reset by target
    TIMEOUT = "timeout"  # No response within timeout window


class CrashConfidence(StrEnum):
    """Confidence level for crash detection."""

    HIGH = "high"  # Multiple workers agree, or control probe failed
    MEDIUM = "medium"  # Consistent timeouts or connection state change
    UNKNOWN = "unknown"  # Single worker signal without corroboration


@dataclass
class CrashSignal:
    """A single crash detection signal from a worker."""

    worker_id: int
    error_type: ErrorType
    consecutive_timeouts: int = 0
    reason: str = ""

    def __post_init__(self) -> None:
        """Validate signal configuration."""
        if self.error_type == ErrorType.TIMEOUT and self.consecutive_timeouts == 0:
            raise ValueError("TIMEOUT error must have consecutive_timeouts > 0")


@dataclass
class CrashEvent:
    """A crash detection event with confidence and reason."""

    confidence: CrashConfidence
    reason: str
    worker_ids: list[int] = field(default_factory=list)
    error_type: ErrorType = ErrorType.TIMEOUT

    def __post_init__(self) -> None:
        """Validate event configuration."""
        if not self.worker_ids:
            raise ValueError("CrashEvent must have at least one worker_id")


class CrashDetector:
    """Detects crashes using multiple signals with configurable confidence thresholds."""

    def __init__(
        self,
        timeout_threshold: int = 3,
        connection_failure_threshold: int = 2,
        worker_agreement_threshold: float = 0.5,
    ) -> None:
        """Initialize crash detector.

        Args:
            timeout_threshold: Consecutive timeouts needed to declare crash (e.g., 3-5)
            connection_failure_threshold: Failed connections needed to declare crash
            worker_agreement_threshold: Fraction of workers needed to agree (0.0-1.0)
        """
        self.timeout_threshold = timeout_threshold
        self.connection_failure_threshold = connection_failure_threshold
        self.worker_agreement_threshold = worker_agreement_threshold

        # Per-worker state tracking
        self.timeout_counters: dict[int, int] = {}
        self.connection_failure_counters: dict[int, int] = {}
        self.worker_signals: dict[int, list[CrashSignal]] = {}

    def record_timeout(self, worker_id: int) -> "CrashEvent | None":
        """Record a timeout for a worker.

        Args:
            worker_id: ID of worker experiencing timeout

        Returns:
            CrashEvent if crash threshold reached, None otherwise
        """
        self.timeout_counters[worker_id] = self.timeout_counters.get(worker_id, 0) + 1
        consecutive = self.timeout_counters[worker_id]

        if consecutive >= self.timeout_threshold:
            signal = CrashSignal(
                worker_id=worker_id,
                error_type=ErrorType.TIMEOUT,
                consecutive_timeouts=consecutive,
                reason=f"{consecutive} consecutive timeouts",
            )
            self._record_signal(worker_id, signal)

            return CrashEvent(
                confidence=CrashConfidence.MEDIUM,
                reason=f"{consecutive} consecutive timeouts from worker {worker_id}",
                worker_ids=[worker_id],
                error_type=ErrorType.TIMEOUT,
            )

        return None

    def record_success(self, worker_id: int) -> None:
        """Record a successful response, resetting timeout counter.

        Args:
            worker_id: ID of worker experiencing success
        """
        self.timeout_counters[worker_id] = 0
        self.connection_failure_counters[worker_id] = 0

    def record_connection_failure(
        self, worker_id: int, failure_type: ErrorType
    ) -> "CrashEvent | None":
        """Record a connection failure for a worker.

        Args:
            worker_id: ID of worker experiencing failure
            failure_type: Type of failure (REFUSED, RESET)

        Returns:
            CrashEvent if crash threshold reached, None otherwise
        """
        if failure_type not in (ErrorType.CONNECTION_REFUSED, ErrorType.CONNECTION_RESET):
            raise ValueError(f"Invalid failure type: {failure_type}")

        self.connection_failure_counters[worker_id] = (
            self.connection_failure_counters.get(worker_id, 0) + 1
        )
        count = self.connection_failure_counters[worker_id]

        if count >= self.connection_failure_threshold:
            signal = CrashSignal(
                worker_id=worker_id,
                error_type=failure_type,
                reason=f"Connection {failure_type.value}",
            )
            self._record_signal(worker_id, signal)

            return CrashEvent(
                confidence=CrashConfidence.MEDIUM,
                reason=f"Connection {failure_type.value} from worker {worker_id}",
                worker_ids=[worker_id],
                error_type=failure_type,
            )

        return None

    def record_hci_error(self, worker_id: int, is_local: bool) -> "CrashEvent | None":
        """Record an HCI error and classify as local or remote.

        Args:
            worker_id: ID of worker experiencing error
            is_local: True if local adapter error, False if remote device error

        Returns:
            CrashEvent for remote errors (medium confidence), None for local
        """
        if is_local:
            # Local errors don't cause crash detection
            return None

        # Remote device errors are crash signals
        signal = CrashSignal(
            worker_id=worker_id,
            error_type=ErrorType.REMOTE_DEVICE_ERROR,
            reason="Remote device HCI error",
        )
        self._record_signal(worker_id, signal)

        return CrashEvent(
            confidence=CrashConfidence.MEDIUM,
            reason=f"Remote device HCI error from worker {worker_id}",
            worker_ids=[worker_id],
            error_type=ErrorType.REMOTE_DEVICE_ERROR,
        )

    def evaluate_worker_corroboration(
        self, worker_ids: list[int]
    ) -> "CrashEvent | None":
        """Evaluate if multiple workers agree on crash (increases confidence).

        Args:
            worker_ids: List of worker IDs to evaluate

        Returns:
            CrashEvent with HIGH confidence if agreement threshold met, None otherwise
        """
        if not worker_ids:
            return None

        # Count workers with crash signals
        workers_with_signals = sum(
            1
            for wid in worker_ids
            if wid in self.worker_signals and len(self.worker_signals[wid]) > 0
        )

        agreement_ratio = workers_with_signals / len(worker_ids)

        if agreement_ratio >= self.worker_agreement_threshold:
            return CrashEvent(
                confidence=CrashConfidence.HIGH,
                reason=f"{workers_with_signals}/{len(worker_ids)} workers detect crash",
                worker_ids=list(range(workers_with_signals)),
                error_type=ErrorType.TIMEOUT,
            )

        return None

    def validate_with_control_probe(
        self, worker_id: int, control_probe_succeeded: bool
    ) -> "CrashEvent | None":
        """Validate crash signal using control probe result.

        Args:
            worker_id: ID of worker that sent control probe
            control_probe_succeeded: True if control probe succeeded (invalidates crash)

        Returns:
            CrashEvent with increased confidence if probe failed, None if succeeded
        """
        if control_probe_succeeded:
            # Control probe succeeded - crash signal is likely false positive
            self.timeout_counters[worker_id] = 0
            return None

        # Control probe failed - increases crash confidence
        if worker_id in self.worker_signals and len(self.worker_signals[worker_id]) > 0:
            return CrashEvent(
                confidence=CrashConfidence.HIGH,
                reason=f"Control probe validation failed for worker {worker_id}",
                worker_ids=[worker_id],
                error_type=ErrorType.TIMEOUT,
            )

        return None

    def _record_signal(self, worker_id: int, signal: CrashSignal) -> None:
        """Record a crash signal for a worker."""
        if worker_id not in self.worker_signals:
            self.worker_signals[worker_id] = []
        self.worker_signals[worker_id].append(signal)

    def reset_worker(self, worker_id: int) -> None:
        """Reset all state for a worker (e.g., after reconnection).

        Args:
            worker_id: ID of worker to reset
        """
        self.timeout_counters[worker_id] = 0
        self.connection_failure_counters[worker_id] = 0
        if worker_id in self.worker_signals:
            self.worker_signals[worker_id].clear()
