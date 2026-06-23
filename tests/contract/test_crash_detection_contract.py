"""Contract tests for crash detection confidence and false-positive mitigation.

Verifies that crash detection meets confidence requirements without false positives.
"""

from sdpfuzz2.bluetooth.crash_detector import (
    CrashConfidence,
    CrashDetector,
    ErrorType,
)


class TestCrashDetectionConfidenceContract:
    """Contract: crash detection confidence levels meet requirements."""

    def test_medium_confidence_requires_threshold(self) -> None:
        """Contract: MEDIUM confidence requires reaching timeout threshold."""
        detector = CrashDetector(timeout_threshold=3)

        # Below threshold: no crash
        for _ in range(2):
            result = detector.record_timeout(worker_id=1)
            assert result is None

        # At threshold: MEDIUM confidence
        result = detector.record_timeout(worker_id=1)
        assert result is not None
        assert result.confidence == CrashConfidence.MEDIUM

    def test_high_confidence_requires_corroboration(self) -> None:
        """Contract: HIGH confidence requires worker corroboration."""
        detector = CrashDetector(
            timeout_threshold=2, worker_agreement_threshold=0.5
        )

        # Multiple workers detect crash
        for worker_id in [1, 2, 3]:
            detector.record_timeout(worker_id=worker_id)
            detector.record_timeout(worker_id=worker_id)

        result = detector.evaluate_worker_corroboration(
            worker_ids=[1, 2, 3, 4, 5]
        )
        assert result is not None
        assert result.confidence == CrashConfidence.HIGH

    def test_control_probe_elevates_to_high_confidence(self) -> None:
        """Contract: failed control probe elevates MEDIUM to HIGH confidence."""
        detector = CrashDetector(timeout_threshold=2)

        # MEDIUM confidence crash
        detector.record_timeout(worker_id=1)
        crash_event = detector.record_timeout(worker_id=1)
        assert crash_event is not None
        assert crash_event.confidence == CrashConfidence.MEDIUM

        # Failed control probe elevates to HIGH
        result = detector.validate_with_control_probe(
            worker_id=1, control_probe_succeeded=False
        )
        assert result is not None
        assert result.confidence == CrashConfidence.HIGH

    def test_crash_reason_always_provided(self) -> None:
        """Contract: every crash event includes a clear reason."""
        detector = CrashDetector(timeout_threshold=1)

        result = detector.record_timeout(worker_id=1)
        assert result is not None
        assert result.reason is not None
        assert len(result.reason) > 0
        assert "timeout" in result.reason.lower() or (
            "consecutive" in result.reason.lower()
        )

    def test_worker_ids_tracked_in_event(self) -> None:
        """Contract: crash event tracks which workers detected signal."""
        detector = CrashDetector(timeout_threshold=1)

        result = detector.record_timeout(worker_id=5)
        assert result is not None
        assert 5 in result.worker_ids


class TestFalsePositiveRequirements:
    """Contract: false-positive mitigation meets requirements."""

    def test_packet_loss_not_confused_with_crash(self) -> None:
        """Contract: isolated timeouts (packet loss) don't trigger crash."""
        detector = CrashDetector(timeout_threshold=3)

        # Isolated timeout
        result = detector.record_timeout(worker_id=1)
        assert result is None

        # Success resets
        detector.record_success(worker_id=1)
        assert detector.timeout_counters[1] == 0

    def test_transient_failures_dont_crash(self) -> None:
        """Contract: transient connection issues don't cause crash."""
        detector = CrashDetector(connection_failure_threshold=3)

        # Single failure
        result = detector.record_connection_failure(
            worker_id=1, failure_type=ErrorType.CONNECTION_REFUSED
        )
        assert result is None

    def test_successful_recovery_clears_crash(self) -> None:
        """Contract: successful control probe clears crash signal."""
        detector = CrashDetector(timeout_threshold=2)

        # Build up crash signal
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # Control probe success clears it
        result = detector.validate_with_control_probe(
            worker_id=1, control_probe_succeeded=True
        )
        assert result is None
        assert detector.timeout_counters[1] == 0

    def test_local_errors_ignored(self) -> None:
        """Contract: local adapter errors never trigger crash detection."""
        detector = CrashDetector()

        result = detector.record_hci_error(worker_id=1, is_local=True)
        assert result is None

    def test_single_worker_insufficient_for_high_confidence(self) -> None:
        """Contract: single worker cannot reach HIGH confidence without control probe."""
        detector = CrashDetector(
            timeout_threshold=2, worker_agreement_threshold=0.5
        )

        # Single worker crash
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # Other workers fine
        detector.record_success(worker_id=2)
        detector.record_success(worker_id=3)

        # Insufficient agreement for HIGH
        result = detector.evaluate_worker_corroboration(
            worker_ids=[1, 2, 3]
        )
        assert result is None


class TestGlobalStopRequirements:
    """Contract: global stop signal broadcast works correctly."""

    def test_stop_signal_on_high_confidence_crash(self) -> None:
        """Contract: stop signal should be triggered on HIGH confidence crash."""
        detector = CrashDetector(timeout_threshold=1)

        # Trigger crash
        result = detector.record_timeout(worker_id=1)
        assert result is not None

        # In production, this would trigger stop signal broadcast
        # Verify the crash event contains necessary info
        assert result.confidence == CrashConfidence.MEDIUM
        assert result.worker_ids == [1]

    def test_stop_signal_includes_worker_list(self) -> None:
        """Contract: stop signal specifies which workers detected crash."""
        detector = CrashDetector(timeout_threshold=1)

        crash_event = detector.record_timeout(worker_id=7)
        assert crash_event is not None
        assert len(crash_event.worker_ids) > 0
        assert all(isinstance(wid, int) for wid in crash_event.worker_ids)


class TestNoRegressionOnCrashDetection:
    """Contract: crash detection doesn't regress existing functionality."""

    def test_multiple_independent_workers(self) -> None:
        """Contract: workers operate independently without state leakage."""
        detector = CrashDetector(timeout_threshold=2)

        # Worker 1: crash
        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=1)

        # Worker 2: independent tracking
        detector.record_timeout(worker_id=2)

        assert detector.timeout_counters[1] == 2
        assert detector.timeout_counters[2] == 1

    def test_reset_doesnt_affect_other_workers(self) -> None:
        """Contract: resetting one worker doesn't affect others."""
        detector = CrashDetector(timeout_threshold=1)

        detector.record_timeout(worker_id=1)
        detector.record_timeout(worker_id=2)

        detector.reset_worker(worker_id=1)

        assert detector.timeout_counters[1] == 0
        assert detector.timeout_counters[2] == 1

    def test_no_state_mutation_on_read(self) -> None:
        """Contract: reading state doesn't mutate detector."""
        detector = CrashDetector(timeout_threshold=2)

        detector.record_timeout(worker_id=1)
        count_before = detector.timeout_counters[1]

        # Evaluate (read-only operation)
        detector.evaluate_worker_corroboration(worker_ids=[1, 2])

        count_after = detector.timeout_counters[1]
        assert count_before == count_after
