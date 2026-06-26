"""Integration tests for FuzzRunner with mock transport and crash detector — task 7.8."""

import asyncio

from sdpfuzz2.bluetooth.crash_detector import CrashDetector
from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.orchestration.runner import FuzzRunner, FuzzRunnerConfig
from sdpfuzz2.orchestration.session import SessionState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class EchoTransport(Transport):
    """Transport that echoes back a valid SDP-like response."""

    def send(self, payload: bytes) -> None:
        pass

    def receive(self, timeout_ms: int) -> bytes:
        # Minimal SDP Service Search Attribute Response
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"

    def close(self) -> None:
        pass


class CrashAfterNTransport(Transport):
    """Transport that succeeds N times then always raises TimeoutError."""

    def __init__(self, succeed_count: int) -> None:
        self._count = 0
        self._limit = succeed_count

    def send(self, payload: bytes) -> None:
        pass

    def receive(self, timeout_ms: int) -> bytes:
        self._count += 1
        if self._count > self._limit:
            raise TimeoutError("timed out")
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_runner_integration_happy_path() -> None:
    """Runner completes cleanly when transport always responds successfully."""

    async def run_test() -> None:
        fuzzer = TotallyRandomBytesStrategy(seed=42)
        runner = FuzzRunner(
            strategy=fuzzer,
            transport_factory=EchoTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=2, queue_size=8),
                max_packets=10,
            ),
        )
        await runner.run()

        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 10
        assert runner.stats.crashes_detected == 0

    asyncio.run(run_test())


def test_runner_integration_crash_stops_run() -> None:
    """Runner stops the fuzzing loop when the crash detector fires."""

    async def run_test() -> None:
        # Crash detected after first timeout (threshold=1)
        detector = CrashDetector(timeout_threshold=1)
        fuzzer = TotallyRandomBytesStrategy(seed=0)

        runner = FuzzRunner(
            strategy=fuzzer,
            transport_factory=lambda: CrashAfterNTransport(succeed_count=2),
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


def test_runner_integration_statistics_accuracy() -> None:
    """Statistics counters reflect actual exchange counts."""

    async def run_test() -> None:
        fuzzer = TotallyRandomBytesStrategy(seed=7)
        runner = FuzzRunner(
            strategy=fuzzer,
            transport_factory=EchoTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=1, queue_size=4),
                max_packets=6,
                stop_on_crash=False,
            ),
        )
        await runner.run()

        assert runner.stats.packets_sent == 6
        # All responses succeeded
        assert runner.stats.errors == 0
        assert runner.stats.timeouts == 0
        assert runner.stats.elapsed_seconds > 0

    asyncio.run(run_test())


def test_runner_integration_multiple_workers() -> None:
    """Runner works correctly with multiple concurrent workers."""

    async def run_test() -> None:
        fuzzer = TotallyRandomBytesStrategy(seed=99)
        runner = FuzzRunner(
            strategy=fuzzer,
            transport_factory=EchoTransport,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=4, queue_size=16),
                max_packets=20,
            ),
        )
        await runner.run()

        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 20

    asyncio.run(run_test())


def test_runner_integration_verify_orchestration() -> None:
    """Task 7.9: Verify runner correctly orchestrates all components."""

    async def run_test() -> None:
        detector = CrashDetector(timeout_threshold=3)
        fuzzer = TotallyRandomBytesStrategy(seed=12)

        runner = FuzzRunner(
            strategy=fuzzer,
            transport_factory=EchoTransport,
            crash_detector=detector,
            config=FuzzRunnerConfig(
                runtime_config=RuntimeConfig(concurrency=2, queue_size=8),
                max_packets=15,
                stop_on_crash=True,
            ),
        )
        await runner.run()

        # All components cooperated — no crash, all packets through
        assert runner.state == SessionState.STOPPED
        assert runner.stats.packets_sent == 15
        assert runner.stats.crashes_detected == 0
        assert runner.stats.elapsed_seconds > 0

    asyncio.run(run_test())
