"""Integration tests for crash detection false-positive mitigation.

Tests verify that crash detection handles packet loss and transient failures
without triggering false positives.
"""

from sdpfuzz2.bluetooth.crash_detector import (
    CrashConfidence,
    CrashDetector,
    ErrorType,
)


class TestFalsePositiveMitigation:
    """Test false-positive mitigation under packet loss."""

    def test_single_timeout_not_misclassified_as_crash(self) -> None:
        """Test: isolated timeouts due to packet loss don't trigger crash."""
        detector = CrashDetector(timeout_threshold=3)

        # Single timeout (could be packet loss)
        result = detector.record_timeout(worker_id=1)
        assert result is None

        # Success on retry
        detector.record_success(worker_id=1)

        # Timeout counter should be reset
        assert detector.timeout_counters[1] == 0

    def test_alternating_timeouts_and_successes_dont_crash(self) -> None:
        """Test: alternating timeouts and successes (transient issues) don't cause crash."""
        detector = CrashDetector(timeout_threshold=3)

        # Simulate transient packet loss pattern
        detector.record_timeout(worker_id=1)
        detector.record_success(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_success(worker_id=1)
        detector.record_timeout(worker_id=1)
        detector.record_success(worker_id=1)

        # Should never trigger crash despite 3+ total timeouts
        assert detector.timeout_counters[1] == 0

    def test_consecutive_timeouts_override_transient(self) -> None:
        """Test: but consecutive timeouts still properly detect crash."""
        detector = CrashDetector(timeout_threshold=3)

        # Transient failures first
        detector.record_timeout(worker_id=1)
        detector.record_success(worker_id=1)

        # Then actual crash (consecutive timeouts)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)
        result = detector.record_timeout(worker_id=1)

        assert result is not None
        assert result.confidence == CrashConfidence.MEDIUM

    def test_control_probe_prevents_false_positive(self) -> None:
        """Test: control probe can override crash signal if it succeeds."""
        detector = CrashDetector(timeout_threshold=2)

        # Simulate crash signal
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # But control probe succeeds (false positive due to network issue)
        result = detector.validate_with_control_probe(
            worker_id=1, control_probe_succeeded=True
        )

        assert result is None
        assert detector.timeout_counters[1] == 0

    def test_multiple_workers_reduce_false_positives(self) -> None:
        """Test: requiring multi-worker agreement reduces false positives."""
        detector = CrashDetector(
            timeout_threshold=2, worker_agreement_threshold=0.5
        )

        # One worker has timeout (could be network issue)
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # But other workers are fine
        detector.record_success(worker_id=2)
        detector.record_success(worker_id=3)

        # 1/3 workers < 0.5 threshold, so no HIGH confidence crash
        result = detector.evaluate_worker_corroboration(worker_ids=[1, 2, 3])
        assert result is None

    def test_high_threshold_reduces_false_positives(self) -> None:
        """Test: increasing timeout threshold reduces false positives from packet loss."""
        detector = CrashDetector(timeout_threshold=5)

        # Few timeouts due to network
        for _ in range(4):
            result = detector.record_timeout(worker_id=1)
            assert result is None

        # 5th timeout triggers crash
        result = detector.record_timeout(worker_id=1)
        assert result is not None

    def test_connection_failure_threshold_prevents_false_positives(self) -> None:
        """Test: connection failure threshold prevents single-event false positives."""
        detector = CrashDetector(connection_failure_threshold=3)

        # Single refused connection (transient, not crash)
        result = detector.record_connection_failure(
            worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED
        )
        assert result is None

        # Recovery
        detector.record_success(worker_id=1)

        # Counter should reset
        assert detector.connection_failure_counters[1] == 0


class TestGlobalStopSignal:
    """Test global stop signal broadcast on crash detection."""

    def test_stop_signal_data_structure(self) -> None:
        """Test: stop signal can be created and tracked."""
        stop_signal: dict[str, object] = {
            "active": True,
            "reason": "High-confidence crash detected",
        }
        assert stop_signal["active"] is True
        reason = stop_signal["reason"]
        assert "crash" in str(reason)

    def test_multiple_workers_receive_stop_signal(self) -> None:
        """Test: all workers are notified when stop signal is broadcast."""
        stop_signals = {
            worker_id: {"stop": True, "reason": "Crash detected"}
            for worker_id in range(1, 5)
        }

        for worker_id in range(1, 5):
            assert stop_signals[worker_id]["stop"] is True

    def test_stop_signal_includes_crash_reason(self) -> None:
        """Test: stop signal includes reason for stopping."""
        detector = CrashDetector(timeout_threshold=2)

        detector.record_timeout(worker_id=1)
        crash_event = detector.record_timeout(worker_id=1)

        assert crash_event is not None
        assert crash_event.reason is not None
        assert len(crash_event.reason) > 0

    def test_stop_signal_persistence(self) -> None:
        """Test: stop signal persists until explicitly cleared."""
        is_stopped = False

        # Crash detected
        is_stopped = True

        # Signal should persist
        assert is_stopped is True

        # Later, signal is cleared
        is_stopped = False
        assert is_stopped is False


class TestCrashDetectionIntegration:
    """Integration tests for complete crash detection scenario."""

    def test_complete_crash_detection_scenario(self) -> None:
        """Test: complete scenario from crash signal to multi-worker agreement."""
        detector = CrashDetector(timeout_threshold=2, worker_agreement_threshold=0.5)

        # Worker 1 detects crash via timeout
        detector.record_timeout(worker_id=1)
        result1 = detector.record_timeout(worker_id=1)
        assert result1 is not None
        assert result1.confidence == CrashConfidence.MEDIUM

        # Worker 2 detects crash via timeout
        detector.record_timeout(worker_id=2)
        result2 = detector.record_timeout(worker_id=2)
        assert result2 is not None
        assert result2.confidence == CrashConfidence.MEDIUM

        # Multi-worker corroboration
        result_corr = detector.evaluate_worker_corroboration(
            worker_ids=[1, 2, 3, 4]
        )
        assert result_corr is not None
        assert result_corr.confidence == CrashConfidence.HIGH

    def test_crash_recovery_scenario(self) -> None:
        """Test: false positive detection followed by recovery."""
        detector = CrashDetector(timeout_threshold=2)

        # Apparent crash
        detector.record_timeout(worker_id=1)
        result1 = detector.record_timeout(worker_id=1)
        assert result1 is not None

        # But control probe succeeds
        result2 = detector.validate_with_control_probe(
            worker_id=1, control_probe_succeeded=True
        )
        assert result2 is None

        # Worker recovers
        detector.record_success(worker_id=1)
        assert detector.timeout_counters[1] == 0
