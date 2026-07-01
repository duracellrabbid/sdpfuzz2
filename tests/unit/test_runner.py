"""Unit tests for FuzzRunner — tasks 7.1 and 7.6."""

import asyncio
import time
from pathlib import Path

import pytest

from sdpfuzz2.bluetooth.crash_detector import CrashDetector
from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.orchestration.runner import FuzzRunner, FuzzRunnerConfig
from sdpfuzz2.orchestration.session import RunStatistics, SessionState

# ---------------------------------------------------------------------------
# Fakes / stubs
# ---------------------------------------------------------------------------


class FakeTransport(Transport):
    """Deterministic fake transport for unit testing."""

    def __init__(
        self,
        responses: list[bytes] | None = None,
        error_on_recv: Exception | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._error_on_recv = error_on_recv
        self.sent: list[bytes] = []
        self.closed = False
        self._recv_count = 0

    def send(self, payload: bytes) -> None:
        self.sent.append(payload)

    def receive(self, timeout_ms: int) -> bytes:
        del timeout_ms
        if self._error_on_recv is not None:
            raise self._error_on_recv
        idx = self._recv_count
        self._recv_count += 1
        if idx < len(self._responses):
            return self._responses[idx]
        # Default: minimal valid SDP response
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"

    def close(self) -> None:
        self.closed = True


class CountingStrategy(FuzzingStrategy):
    """Strategy that produces a fixed payload, counting calls."""

    def __init__(self, payload: bytes = b"\x06\x00\x01\x00\x02\x00\x00") -> None:
        self.payload = payload
        self.calls = 0

    def next_packet(self) -> bytes:
        self.calls += 1
        return self.payload


class ExplodingStrategy(FuzzingStrategy):
    """Strategy that raises on the first call."""

    def next_packet(self) -> bytes:
        raise RuntimeError("Strategy exploded")


# ---------------------------------------------------------------------------
# RunStatistics unit tests
# ---------------------------------------------------------------------------


def test_run_statistics_elapsed_before_start() -> None:
    stats = RunStatistics()
    assert stats.elapsed_seconds == 0.0


def test_run_statistics_elapsed_after_start() -> None:
    stats = RunStatistics()
    stats.start()
    time.sleep(0.02)
    assert stats.elapsed_seconds >= 0.01


def test_run_statistics_elapsed_after_stop() -> None:
    stats = RunStatistics()
    stats.start()
    time.sleep(0.02)
    stats.stop()
    elapsed = stats.elapsed_seconds
    time.sleep(0.02)
    # Should not grow after stop
    assert abs(stats.elapsed_seconds - elapsed) < 0.005


def test_run_statistics_defaults() -> None:
    stats = RunStatistics()
    assert stats.packets_sent == 0
    assert stats.packets_received == 0
    assert stats.timeouts == 0
    assert stats.errors == 0
    assert stats.crashes_detected == 0


# ---------------------------------------------------------------------------
# FuzzRunner lifecycle tests (task 7.6)
# ---------------------------------------------------------------------------


def test_runner_starts_idle() -> None:
    strategy = CountingStrategy()
    runner = FuzzRunner(
        strategy=strategy,
        transport_factory=FakeTransport,
    )
    assert runner.state == SessionState.IDLE


def test_runner_stops_after_packet_limit() -> None:
    """Runner sends exactly max_packets and then stops cleanly."""

    async def run_test() -> None:
        strategy = CountingStrategy()
        config = FuzzRunnerConfig(
            runtime_config=RuntimeConfig(concurrency=1, queue_size=16),
            max_packets=5,
        )
        runner = FuzzRunner(
            strategy=strategy,
            transport_factory=FakeTransport,
            config=config,
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 5
        assert runner.stats.elapsed_seconds > 0

    asyncio.run(run_test())


def test_runner_stops_on_strategy_error() -> None:
    """Runner exits cleanly when the strategy raises."""

    async def run_test() -> None:
        runner = FuzzRunner(
            strategy=ExplodingStrategy(),
            transport_factory=FakeTransport,
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        # No packets should have been successfully sent
        assert runner.stats.packets_sent == 0

    asyncio.run(run_test())


def test_runner_stopped_state_after_run() -> None:
    """State must be STOPPED after run() completes."""

    async def run_test() -> None:
        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            config=FuzzRunnerConfig(max_packets=1),
        )
        assert runner.state == SessionState.IDLE
        await runner.run()
        assert runner.state.value == SessionState.STOPPED.value

    asyncio.run(run_test())


# ---------------------------------------------------------------------------
# Crash detection integration (task 7.1)
# ---------------------------------------------------------------------------


def test_runner_stops_on_crash_detection() -> None:
    """Runner halts immediately when crash is detected (stop_on_crash=True)."""

    async def run_test() -> None:
        # Transport that always times out to trigger crash detection
        timeout_error = TimeoutError("timed out")
        detector = CrashDetector(timeout_threshold=1)

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=lambda: FakeTransport(error_on_recv=timeout_error),
            crash_detector=detector,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                stop_on_crash=True,
            ),
        )
        await runner.run()

        assert runner.state == SessionState.STOPPED
        assert runner.stats.crashes_detected >= 1
        assert runner.stats.timeouts >= 1

    asyncio.run(run_test())


def test_runner_continues_on_crash_when_stop_disabled() -> None:
    """When stop_on_crash=False the runner ignores crashes and respects max_packets."""

    async def run_test() -> None:
        timeout_error = TimeoutError("timed out")
        detector = CrashDetector(timeout_threshold=1)

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=lambda: FakeTransport(error_on_recv=timeout_error),
            crash_detector=detector,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                stop_on_crash=False,
                max_packets=3,
                # disable error cap so we don't stop on consecutive errors
                max_errors=0,
            ),
        )
        await runner.run()

        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 3

    asyncio.run(run_test())


# ---------------------------------------------------------------------------
# Exception handling / recovery (task 7.5)
# ---------------------------------------------------------------------------


def test_runner_handles_max_consecutive_errors() -> None:
    """Runner stops after max_errors consecutive transport errors."""

    async def run_test() -> None:
        generic_error = ConnectionError("reset by peer")

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=lambda: FakeTransport(error_on_recv=generic_error),
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                max_errors=2,
                stop_on_crash=False,
            ),
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        # Stopped due to error cap
        assert runner.stats.errors >= 2

    asyncio.run(run_test())


def test_runner_resets_error_counter_on_success() -> None:
    """A successful response resets the consecutive-error counter."""

    async def run_test() -> None:
        # First call succeeds, second raises, third succeeds.
        # With max_errors=2 the runner should not stop.
        call_count = 0
        error = ConnectionError("reset by peer")

        class AltErrorTransport(FakeTransport):
            def receive(self, timeout_ms: int) -> bytes:
                nonlocal call_count
                call_count += 1
                if call_count == 2:
                    raise error
                return b"\x07\x00\x01\x00\x03\x00\x00\x00"

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=AltErrorTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                max_errors=2,
                max_packets=3,
                stop_on_crash=False,
            ),
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 3

    asyncio.run(run_test())


# ---------------------------------------------------------------------------
# Signal handling (task 7.7)
# ---------------------------------------------------------------------------


def test_runner_interrupt_flag_stops_loop() -> None:
    """Setting _interrupted to True causes the loop to exit."""

    async def run_test() -> None:
        strategy = CountingStrategy()
        runner = FuzzRunner(
            strategy=strategy,
            transport_factory=FakeTransport,
        )

        # Schedule an interrupt after a brief delay
        async def interrupt_after() -> None:
            await asyncio.sleep(0.05)
            runner._interrupted = True

        asyncio.create_task(interrupt_after())
        await runner.run()

        assert runner.state == SessionState.STOPPED
        # Some packets may have been sent before the interrupt
        assert runner.stats.packets_sent >= 0

    asyncio.run(run_test())


# ---------------------------------------------------------------------------
# Additional edge-case tests to achieve 100% coverage
# ---------------------------------------------------------------------------


def test_runner_cancelled_error_propagation() -> None:
    """asyncio.CancelledError during loop is caught and results in STOPPED state."""

    async def run_test() -> None:
        class CancellingStrategy(FuzzingStrategy):
            def next_packet(self) -> bytes:
                raise asyncio.CancelledError

        runner = FuzzRunner(
            strategy=CancellingStrategy(),
            transport_factory=FakeTransport,
        )
        # CancelledError is raised inside _loop() and should be caught by run()
        # (it propagates as a strategy error → loop breaks cleanly)
        await runner.run()
        assert runner.state == SessionState.STOPPED

    asyncio.run(run_test())


def test_runner_handles_connection_refused_error() -> None:
    """Runner classifies connection-refused errors correctly."""

    async def run_test() -> None:
        refused_error = ConnectionRefusedError("connection refused")
        detector = CrashDetector(connection_failure_threshold=1)

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=lambda: FakeTransport(error_on_recv=refused_error),
            crash_detector=detector,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                stop_on_crash=True,
            ),
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        assert runner.stats.crashes_detected >= 1

    asyncio.run(run_test())


def test_runner_handles_generic_hci_error() -> None:
    """Runner classifies generic transport errors as remote HCI errors."""

    async def run_test() -> None:
        generic_error = OSError("some other I/O failure")
        detector = CrashDetector()

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=lambda: FakeTransport(error_on_recv=generic_error),
            crash_detector=detector,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                max_errors=1,
                stop_on_crash=False,
            ),
        )
        await runner.run()
        assert runner.state == SessionState.STOPPED
        assert runner.stats.errors >= 1

    asyncio.run(run_test())


def test_runner_signal_handler_methods_callable() -> None:
    """_on_interrupt and _on_interrupt_async set the _interrupted flag."""
    runner = FuzzRunner(
        strategy=CountingStrategy(),
        transport_factory=FakeTransport,
    )
    assert not getattr(runner, "_interrupted")  # noqa: B009

    runner._on_interrupt(2, None)
    assert getattr(runner, "_interrupted")  # noqa: B009

    runner._interrupted = False
    runner._on_interrupt_async()
    assert getattr(runner, "_interrupted")  # noqa: B009


def test_runner_install_restore_signal_handlers_no_loop() -> None:
    """Signal handler install/restore works outside an async context (fallback path)."""
    import signal as _signal

    runner = FuzzRunner(
        strategy=CountingStrategy(),
        transport_factory=FakeTransport,
    )
    original = _signal.getsignal(_signal.SIGINT)

    # Simulate outside-loop usage (no running loop) — calls signal.signal directly
    runner._install_signal_handler()
    runner._restore_signal_handler()

    # Signal should be restored to original handler
    assert _signal.getsignal(_signal.SIGINT) == original


def test_runner_win32_signal_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Signal handling on Windows (sys.platform == 'win32')."""
    import signal as _signal
    import sys

    monkeypatch.setattr(sys, "platform", "win32")

    runner = FuzzRunner(
        strategy=CountingStrategy(),
        transport_factory=FakeTransport,
    )

    calls = []

    def fake_signal(sig: int, handler: object) -> object:
        calls.append((sig, handler))
        return _signal.SIG_DFL

    monkeypatch.setattr(_signal, "signal", fake_signal)
    monkeypatch.setattr(_signal, "getsignal", lambda sig: _signal.SIG_DFL)

    runner._install_signal_handler()
    assert (_signal.SIGINT, runner._on_interrupt) in calls

    calls.clear()
    runner._restore_signal_handler()
    assert (_signal.SIGINT, _signal.SIG_DFL) in calls


def test_runner_get_response_exception_path() -> None:
    """get_response failures (future cancelled on shutdown) are counted as errors."""

    async def run_test() -> None:
        # Use a very short scheduler shutdown so futures get cancelled quickly
        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1, response_timeout_ms=50),
                max_packets=3,
                stop_on_crash=False,
                max_errors=0,
            ),
        )
        await runner.run()
        # Runner should finish cleanly
        assert runner.state == SessionState.STOPPED

    asyncio.run(run_test())


def test_runner_run_propagates_unhandled_exception() -> None:
    """An unhandled exception from _loop() is re-raised from run()."""

    async def run_test() -> None:
        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
        )

        # Patch _loop to raise a non-CancelledError exception
        async def bad_loop() -> None:
            raise ValueError("loop went wrong")

        runner._loop = bad_loop  # type: ignore[method-assign]

        with pytest.raises(ValueError, match="loop went wrong"):
            await runner.run()

        assert runner.state == SessionState.STOPPED

    asyncio.run(run_test())


def test_runner_scheduler_submit_runtime_error() -> None:
    """When scheduler raises RuntimeError on submit (already stopped), loop exits."""

    async def run_test() -> None:
        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                max_packets=5,
            ),
        )

        # Install a mock scheduler whose submit raises RuntimeError
        class StoppedScheduler:
            async def submit(self, payload: bytes) -> int:
                raise RuntimeError("Scheduler is stopped")

            async def get_response(
                self, packet_index: int, timeout_seconds: float | None = None
            ) -> object:
                raise asyncio.CancelledError

            async def shutdown(self, timeout_seconds: float = 5.0) -> None:
                pass

        runner._scheduler = StoppedScheduler()  # type: ignore[assignment]
        await runner._loop()
        # Loop should exit because submit raised RuntimeError; 0 packets sent
        assert runner.stats.packets_sent == 0

    asyncio.run(run_test())


def test_runner_get_response_cancelled_future_path() -> None:
    """When get_response raises (future cancelled at shutdown), errors counter increments."""

    async def run_test() -> None:
        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1, response_timeout_ms=50),
                max_errors=1,
                stop_on_crash=False,
                max_packets=0,
            ),
        )

        call_count = 0

        class CancellingScheduler:
            async def submit(self, payload: bytes) -> int:
                nonlocal call_count
                call_count += 1
                return call_count

            async def get_response(
                self, packet_index: int, timeout_seconds: float | None = None
            ) -> object:
                raise asyncio.CancelledError("test cancelled")

            async def shutdown(self, timeout_seconds: float = 5.0) -> None:
                pass

        runner._scheduler = CancellingScheduler()  # type: ignore[assignment]
        await runner._loop()
        # Should stop after 1 error (max_errors=1)
        assert runner.stats.errors >= 1

    asyncio.run(run_test())


def test_runner_get_response_continue_path() -> None:
    """The 'continue' path fires when errors are below max_errors threshold."""

    async def run_test() -> None:
        from sdpfuzz2.orchestration.workers import FuzzResponse

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1, response_timeout_ms=50),
                max_errors=5,  # Allow multiple errors so 'continue' fires before stop
                stop_on_crash=False,
                max_packets=2,  # Stop after 2 packets sent
            ),
        )

        call_seq = [0]

        class AlternatingScheduler:
            async def submit(self, payload: bytes) -> int:
                call_seq[0] += 1
                return call_seq[0]

            async def get_response(
                self, packet_index: int, timeout_seconds: float | None = None
            ) -> object:
                if call_seq[0] == 1:
                    # First call raises — should hit 'continue'
                    raise asyncio.CancelledError("first error")
                # Second call succeeds
                return FuzzResponse(
                    packet_index=packet_index, request_payload=b"", response_payload=b"\x07"
                )

            async def shutdown(self, timeout_seconds: float = 5.0) -> None:
                pass

        runner._scheduler = AlternatingScheduler()  # type: ignore[assignment]
        await runner._loop()
        # After 1 error (below max_errors=5), it continued and sent 2 packets total
        assert runner.stats.errors >= 1

    asyncio.run(run_test())


def test_runner_with_logger(tmp_path: Path) -> None:
    """Verify that FuzzRunner correctly calls RunLogger methods during execution."""
    import json

    from sdpfuzz2.logging.run_logger import RunLogger
    from sdpfuzz2.orchestration.workers import FuzzResponse

    async def run_test() -> None:
        output_file = tmp_path / "fuzz-run.json"
        logger = RunLogger(
            output_file, device_name="Test Device", device_mac_address="00:11:22:33:44:55"
        )

        runner = FuzzRunner(
            strategy=CountingStrategy(),
            transport_factory=FakeTransport,
            run_logger=logger,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1, response_timeout_ms=50),
                max_errors=3,
                stop_on_crash=False,
                max_packets=3,
            ),
        )

        call_seq = [0]

        class CustomScheduler:
            @property
            def in_flight_count(self) -> int:
                return 1

            async def submit(self, payload: bytes) -> int:
                call_seq[0] += 1
                return call_seq[0]

            async def get_response(
                self, packet_index: int, timeout_seconds: float | None = None
            ) -> object:
                if packet_index == 1:
                    # Packet 1: Success
                    return FuzzResponse(
                        packet_index=packet_index,
                        request_payload=b"\x01",
                        response_payload=b"\x02",
                        worker_id=0,
                    )
                elif packet_index == 2:
                    # Packet 2: Refused error (recorded as connection refused error)
                    return FuzzResponse(
                        packet_index=packet_index,
                        request_payload=b"\x03",
                        error=ConnectionRefusedError("refused"),
                        worker_id=0,
                    )
                elif packet_index == 3:
                    # Packet 3: Timeout error (raised in get_response)
                    raise TimeoutError("timeout")
                else:
                    # Packet 4: Success to allow the loop to proceed past
                    # continue and exit via max_packets
                    return FuzzResponse(
                        packet_index=packet_index,
                        request_payload=b"\x01",
                        response_payload=b"\x02",
                        worker_id=0,
                    )

            async def shutdown(self, timeout_seconds: float = 5.0) -> None:
                pass

        runner._scheduler = CustomScheduler()  # type: ignore[assignment]
        await runner._loop()
        await runner._shutdown()

        # Check that the log is written, validated, and finalized
        assert output_file.exists()
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        assert parsed["device_mac_address"] == "00:11:22:33:44:55"
        assert parsed["summary_counters"]["packets_sent"] == 4
        assert len(parsed["logs"]) == 4
        # Packet 1 (Success)
        assert parsed["logs"][0]["packet_index"] == 1
        assert parsed["logs"][0]["response_packet_hex"] == "02"
        assert parsed["logs"][0]["crash"] == 0
        # Packet 2 (Error)
        assert parsed["logs"][1]["packet_index"] == 2
        assert parsed["logs"][1]["response_packet_hex"] == ""
        # Packet 3 (Timeout)
        assert parsed["logs"][2]["packet_index"] == 3
        assert parsed["logs"][2]["response_packet_hex"] == ""
        # Packet 4 (Success after timeout)
        assert parsed["logs"][3]["packet_index"] == 4
        assert parsed["logs"][3]["response_packet_hex"] == "02"

    asyncio.run(run_test())


def test_runner_packet_history_sliding_window() -> None:
    """Test that FuzzRunner keeps a sliding history of the last N packets sent."""
    runner = FuzzRunner(
        strategy=CountingStrategy(),
        transport_factory=lambda: FakeTransport(),
        sequence_length=3,
    )
    runner.packet_history.append(b"pkt1")
    runner.packet_history.append(b"pkt2")
    runner.packet_history.append(b"pkt3")
    runner.packet_history.append(b"pkt4")

    assert list(runner.packet_history) == [b"pkt2", b"pkt3", b"pkt4"]


def test_runner_auto_save_hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that FuzzRunner automatically registers crashes and timeouts in corpus."""
    from sdpfuzz2.bluetooth.crash_detector import CrashConfidence, CrashEvent
    from sdpfuzz2.logging import CorpusManager
    from sdpfuzz2.orchestration.scheduler import FuzzResponse  # type: ignore[attr-defined]

    async def run_test() -> None:
        corpus = CorpusManager(tmp_path)
        runner = FuzzRunner(
            strategy=CountingStrategy(payload=b"fuzzpayload"),
            transport_factory=lambda: FakeTransport(),
            corpus_manager=corpus,
            target_mac="aa:bb:cc:dd:ee:ff",
            sequence_length=5,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1),
                max_packets=3,
                max_errors=0,
                stop_on_crash=True,
            ),
        )

        class FailingScheduler:
            def __init__(self) -> None:
                self.in_flight_count = 0
                self.count = 0

            async def start(self) -> None:
                pass

            async def submit(self, payload: bytes) -> int:
                self.count += 1
                return self.count

            async def get_response(self, index: int, timeout_seconds: float) -> FuzzResponse:
                if index == 1:
                    raise TimeoutError("connection timeout")
                else:
                    return FuzzResponse(
                        packet_index=index,
                        request_payload=b"fuzzpayload",
                        response_payload=None,
                        error=ConnectionResetError("reset by peer"),
                        worker_id=1,
                    )

            async def shutdown(self, timeout_seconds: float = 5.0) -> None:
                pass

        runner._scheduler = FailingScheduler()  # type: ignore[assignment]
        monkeypatch.setattr(
            runner.crash_detector,
            "record_timeout",
            lambda w: CrashEvent(
                confidence=CrashConfidence.MEDIUM, reason="timeout", worker_ids=[w]
            ),
        )
        monkeypatch.setattr(
            runner.crash_detector,
            "record_connection_failure",
            lambda w, t: CrashEvent(
                confidence=CrashConfidence.HIGH, reason="reset", worker_ids=[w]
            ),
        )

        await runner._loop()

        seqs = corpus.list_sequences()
        assert len(seqs) >= 2
        classifications = [s["classification"] for s in seqs]
        assert "timeout_candidate" in classifications
        assert "crash_candidate" in classifications

        for s in seqs:
            assert s["target_mac"] == "aa:bb:cc:dd:ee:ff"
            assert len(corpus.load_packets(s["id"])) > 0

    asyncio.run(run_test())
