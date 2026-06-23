"""Unit tests for crash detection with simulated crash scenarios.

Tests verify timeout-based detection, connection-state detection, HCI error
classification, confidence scoring, and worker corroboration.
"""

import pytest

from sdpfuzz2.bluetooth.crash_detector import (
    CrashConfidence,
    CrashDetector,
    CrashEvent,
    CrashSignal,
    ErrorType,
)


class TestCrashDetectorBasics:
    """Test basic crash detector initialization and state tracking."""

    def test_detector_initializes_with_defaults(self) -> None:
        """Test: detector initializes with reasonable defaults."""
        detector = CrashDetector()

        assert detector.timeout_threshold == 3
        assert detector.connection_failure_threshold == 2
        assert detector.worker_agreement_threshold == 0.5

    def test_detector_accepts_custom_thresholds(self) -> None:
        """Test: detector accepts custom configuration."""
        detector = CrashDetector(
            timeout_threshold=5,
            connection_failure_threshold=3,
            worker_agreement_threshold=0.7,
        )

        assert detector.timeout_threshold == 5
        assert detector.connection_failure_threshold == 3
        assert detector.worker_agreement_threshold == 0.7


class TestTimeoutBasedDetection:
    """Test timeout-based crash detection scenarios."""

    def test_single_timeout_not_crash(self) -> None:
        """Test: single timeout below threshold is not a crash."""
        detector = CrashDetector(timeout_threshold=3)
        result = detector.record_timeout(worker_id=1)

        assert result is None

    def test_multiple_timeouts_below_threshold(self) -> None:
        """Test: timeouts below threshold do not trigger crash."""
        detector = CrashDetector(timeout_threshold=3)

        for _ in range(2):
            result = detector.record_timeout(worker_id=1)
            assert result is None

    def test_timeout_threshold_triggers_crash(self) -> None:
        """Test: reaching timeout threshold declares crash with MEDIUM confidence."""
        detector = CrashDetector(timeout_threshold=3)

        for _ in range(2):
            result = detector.record_timeout(worker_id=1)
            assert result is None

        result = detector.record_timeout(worker_id=1)
        assert result is not None
        assert isinstance(result, CrashEvent)
        assert result.confidence == CrashConfidence.MEDIUM
        assert "3 consecutive timeouts" in result.reason
        assert result.worker_ids == [1]
        assert result.error_type == ErrorType.TIMEOUT

    def test_success_resets_timeout_counter(self) -> None:
        """Test: successful response resets timeout counter to zero."""
        detector = CrashDetector(timeout_threshold=3)

        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_success(worker_id=1)

        # Counter should reset, so next timeout is 1 again
        result = detector.record_timeout(worker_id=1)
        assert result is None

        result = detector.record_timeout(worker_id=1)
        assert result is None

        result = detector.record_timeout(worker_id=1)
        assert result is not None

    def test_per_worker_timeout_tracking(self) -> None:
        """Test: timeout counters are maintained separately per worker."""
        detector = CrashDetector(timeout_threshold=2)

        # Worker 1: 2 timeouts
        detector.record_timeout(worker_id=1)
        result1 = detector.record_timeout(worker_id=1)
        assert result1 is not None
        assert result1.worker_ids == [1]

        # Worker 2: should not be affected
        result2 = detector.record_timeout(worker_id=2)
        assert result2 is None


class TestConnectionFailureDetection:
    """Test connection-state crash detection."""

    def test_single_connection_failure_not_crash(self) -> None:
        """Test: single connection failure below threshold is not crash."""
        detector = CrashDetector(connection_failure_threshold=2)

        result = detector.record_connection_failure(
            worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED
        )
        assert result is None

    def test_connection_refused_threshold_triggers_crash(self) -> None:
        """Test: repeated connection refused reaches threshold."""
        detector = CrashDetector(connection_failure_threshold=2)

        detector.record_connection_failure(worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED)
        result = detector.record_connection_failure(
            worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED
        )

        assert result is not None
        assert result.confidence == CrashConfidence.MEDIUM
        assert "connection_refused" in result.reason

    def test_connection_reset_triggers_crash(self) -> None:
        """Test: connection reset is also a crash signal."""
        detector = CrashDetector(connection_failure_threshold=2)

        detector.record_connection_failure(worker_id=2, failure_type=ErrorType.CONNECTION_RESET)
        result = detector.record_connection_failure(
            worker_id=2, failure_type=ErrorType.CONNECTION_RESET
        )

        assert result is not None
        assert result.error_type == ErrorType.CONNECTION_RESET

    def test_invalid_failure_type_raises_error(self) -> None:
        """Test: invalid failure type raises ValueError."""
        detector = CrashDetector()

        with pytest.raises(ValueError, match="Invalid failure type"):
            detector.record_connection_failure(worker_id=1, failure_type=ErrorType.TIMEOUT)

    def test_success_resets_connection_counter(self) -> None:
        """Test: successful response resets connection failure counter."""
        detector = CrashDetector(connection_failure_threshold=2)

        detector.record_connection_failure(worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED)
        detector.record_success(worker_id=1)

        # Counter should reset
        result = detector.record_connection_failure(
            worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED
        )
        assert result is None


class TestHCIErrorClassification:
    """Test HCI error classification."""

    def test_local_adapter_error_ignored(self) -> None:
        """Test: local adapter errors do not trigger crash detection."""
        detector = CrashDetector()

        result = detector.record_hci_error(worker_id=1, is_local=True)
        assert result is None

    def test_remote_device_error_triggers_crash(self) -> None:
        """Test: remote device errors trigger crash with MEDIUM confidence."""
        detector = CrashDetector()

        result = detector.record_hci_error(worker_id=1, is_local=False)

        assert result is not None
        assert result.confidence == CrashConfidence.MEDIUM
        assert result.error_type == ErrorType.REMOTE_DEVICE_ERROR
        assert "Remote device HCI error" in result.reason


class TestCrashConfidenceScoring:
    """Test crash confidence scoring."""

    def test_crash_signal_dataclass(self) -> None:
        """Test: CrashSignal validates configuration."""
        signal = CrashSignal(
            worker_id=1,
            error_type=ErrorType.TIMEOUT,
            consecutive_timeouts=3,
            reason="3 timeouts",
        )
        assert signal.consecutive_timeouts == 3

    def test_crash_signal_timeout_requires_count(self) -> None:
        """Test: TIMEOUT error requires consecutive_timeouts > 0."""
        with pytest.raises(ValueError, match="consecutive_timeouts"):
            CrashSignal(worker_id=1, error_type=ErrorType.TIMEOUT, consecutive_timeouts=0)

    def test_crash_event_requires_worker_ids(self) -> None:
        """Test: CrashEvent requires at least one worker_id."""
        with pytest.raises(ValueError, match="must have at least one worker_id"):
            CrashEvent(
                confidence=CrashConfidence.HIGH,
                reason="test",
                worker_ids=[],
            )

    def test_crash_event_with_valid_data(self) -> None:
        """Test: CrashEvent accepts valid configuration."""
        event = CrashEvent(
            confidence=CrashConfidence.HIGH,
            reason="Multiple workers detect crash",
            worker_ids=[1, 2, 3],
        )
        assert len(event.worker_ids) == 3


class TestWorkerCorroboration:
    """Test multi-worker corroboration logic."""

    def test_corroboration_with_single_worker(self) -> None:
        """Test: single worker with crash signal below agreement threshold."""
        detector = CrashDetector(worker_agreement_threshold=0.5)

        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        result = detector.evaluate_worker_corroboration(worker_ids=[1, 2, 3, 4])
        assert result is None  # 1/4 < 0.5

    def test_corroboration_with_multiple_workers(self) -> None:
        """Test: multiple workers reaching threshold increases confidence."""
        detector = CrashDetector(timeout_threshold=2, worker_agreement_threshold=0.5)

        # Two workers detect crashes
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=2)
        detector.record_timeout(worker_id=2)

        result = detector.evaluate_worker_corroboration(worker_ids=[1, 2, 3, 4])

        assert result is not None
        assert result.confidence == CrashConfidence.HIGH
        assert "2/4 workers detect crash" in result.reason

    def test_corroboration_with_100_percent_threshold(self) -> None:
        """Test: 100% agreement threshold requires all workers."""
        detector = CrashDetector(timeout_threshold=2, worker_agreement_threshold=1.0)

        # Two workers out of four detect crashes
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=2)
        detector.record_timeout(worker_id=2)

        result = detector.evaluate_worker_corroboration(worker_ids=[1, 2, 3, 4])
        assert result is None  # 2/4 < 1.0

    def test_corroboration_with_empty_worker_list(self) -> None:
        """Test: empty worker list returns None."""
        detector = CrashDetector()
        result = detector.evaluate_worker_corroboration(worker_ids=[])
        assert result is None


class TestControlProbeValidation:
    """Test control probe validation logic."""

    def test_control_probe_success_clears_crash(self) -> None:
        """Test: successful control probe invalidates crash signal."""
        detector = CrashDetector(timeout_threshold=2)

        # Simulate crash signal
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # Control probe succeeds
        result = detector.validate_with_control_probe(worker_id=1, control_probe_succeeded=True)

        assert result is None
        assert detector.timeout_counters[1] == 0

    def test_control_probe_failure_increases_confidence(self) -> None:
        """Test: failed control probe increases crash confidence to HIGH."""
        detector = CrashDetector(timeout_threshold=2)

        # Simulate crash signal
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # Control probe fails
        result = detector.validate_with_control_probe(worker_id=1, control_probe_succeeded=False)

        assert result is not None
        assert result.confidence == CrashConfidence.HIGH
        assert "Control probe validation failed" in result.reason

    def test_control_probe_without_prior_signal(self) -> None:
        """Test: control probe on worker without crash signal returns None."""
        detector = CrashDetector()

        result = detector.validate_with_control_probe(worker_id=1, control_probe_succeeded=False)

        assert result is None


class TestWorkerStateReset:
    """Test worker state reset functionality."""

    def test_reset_worker_clears_counters(self) -> None:
        """Test: reset_worker clears all state for a worker."""
        detector = CrashDetector(timeout_threshold=2, connection_failure_threshold=1)

        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_connection_failure(worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED)

        detector.reset_worker(worker_id=1)

        assert detector.timeout_counters[1] == 0
        assert detector.connection_failure_counters[1] == 0
        if 1 in detector.worker_signals:
            assert len(detector.worker_signals[1]) == 0

    def test_reset_only_affects_specified_worker(self) -> None:
        """Test: resetting one worker doesn't affect others."""
        detector = CrashDetector(timeout_threshold=2)

        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=2)

        detector.reset_worker(worker_id=1)

        # Worker 2 should still have timeout count
        assert detector.timeout_counters.get(2, 0) == 1
        assert detector.timeout_counters[1] == 0
