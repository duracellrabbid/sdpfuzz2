"""Fuzz runner — orchestrates strategy, scheduler, crash detection, and logging."""

import asyncio
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

import structlog

from sdpfuzz2.bluetooth.crash_detector import CrashConfidence, CrashDetector, ErrorType
from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.logging.run_logger import RunLogger
from sdpfuzz2.orchestration.scheduler import WorkerScheduler
from sdpfuzz2.orchestration.session import RunStatistics, SessionState

logger = structlog.get_logger()


@dataclass
class FuzzRunnerConfig:
    """Configuration for the FuzzRunner.

    Attributes:
        runtime_config: Concurrency, queue size, and timeout settings.
        max_packets: Stop after sending this many packets (0 = unlimited).
        max_errors: Stop after this many consecutive transport errors (0 = unlimited).
        stop_on_crash: Halt the run immediately on any detected crash.
    """

    runtime_config: RuntimeConfig = field(default_factory=RuntimeConfig)
    max_packets: int = 0
    max_errors: int = 10
    stop_on_crash: bool = True


class FuzzRunner:
    """Coordinates strategy, transport, crash detection, and optional logging.

    Usage::

        runner = FuzzRunner(
            strategy=my_strategy,
            transport_factory=lambda: MyTransport(...),
            crash_detector=CrashDetector(),
        )
        asyncio.run(runner.run())
    """

    def __init__(
        self,
        strategy: FuzzingStrategy,
        transport_factory: Callable[[], Transport],
        crash_detector: CrashDetector | None = None,
        run_logger: RunLogger | None = None,
        config: FuzzRunnerConfig | None = None,
        delay_ms: float = 0.0,
        rate_limit: int = 0,
    ) -> None:
        self.strategy = strategy
        self.transport_factory = transport_factory
        self.crash_detector = crash_detector or CrashDetector()
        self.run_logger = run_logger
        self.config = config or FuzzRunnerConfig()
        self.delay_ms = delay_ms
        self.rate_limit = rate_limit

        self.stats = RunStatistics()
        self.state: SessionState = SessionState.IDLE
        self._scheduler: WorkerScheduler | None = None
        self._interrupted = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the runner, execute the fuzzing loop, then shut down cleanly.

        Installs a SIGINT handler so that Ctrl+C triggers a graceful stop rather
        than an abrupt crash.  The handler is restored on exit.
        """
        self._install_signal_handler()
        self.state = SessionState.RUNNING
        self.stats.start()
        logger.info("FuzzRunner starting", state=self.state)

        self._scheduler = WorkerScheduler(
            config=self.config.runtime_config,
            transport_factory=self.transport_factory,
            delay_ms=self.delay_ms,
            rate_limit=self.rate_limit,
        )

        try:
            await self._scheduler.start()
            await self._loop()
        except asyncio.CancelledError:
            logger.info("FuzzRunner cancelled")
        except Exception as exc:
            logger.error("FuzzRunner unhandled exception", error=str(exc))
            raise
        finally:
            await self._shutdown()
            self._restore_signal_handler()

    async def _loop(self) -> None:
        """Inner fuzzing loop — submits packets and processes responses."""
        consecutive_errors = 0

        while not self._should_stop():
            # Obtain the next packet from the strategy
            try:
                payload = self.strategy.next_packet()
            except Exception as exc:
                logger.error("Strategy error", error=str(exc))
                break

            # Submit to the scheduler (blocks if queue is full — backpressure)
            try:
                packet_index = await self._scheduler.submit(payload)  # type: ignore[union-attr]
            except RuntimeError:
                # Scheduler was stopped concurrently
                break

            self.stats.packets_sent += 1

            # Await the response with a generous timeout to keep the loop moving
            response_timeout = self.config.runtime_config.response_timeout_ms / 1000.0 + 1.0
            try:
                resp = await self._scheduler.get_response(  # type: ignore[union-attr]
                    packet_index, timeout_seconds=response_timeout
                )
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception) as exc:
                self.stats.errors += 1
                consecutive_errors += 1
                logger.warning("Response retrieval error", error=str(exc))
                if (
                    self.config.max_errors > 0
                    and consecutive_errors >= self.config.max_errors
                ):
                    logger.error(
                        "Max consecutive errors reached, stopping",
                        max_errors=self.config.max_errors,
                    )
                    break
                continue

            # Classify the response and update crash detector
            if resp.error is not None:
                self.stats.errors += 1
                consecutive_errors += 1
                crash_event = self._handle_response_error(resp.error, resp.worker_id or 0)
                if crash_event and self.config.stop_on_crash:
                    self.stats.crashes_detected += 1
                    logger.warning(
                        "Crash detected, stopping",
                        confidence=crash_event.confidence,
                        reason=crash_event.reason,
                    )
                    break
                if (
                    self.config.max_errors > 0
                    and consecutive_errors >= self.config.max_errors
                ):
                    logger.error(
                        "Max consecutive errors reached, stopping",
                        max_errors=self.config.max_errors,
                    )
                    break
            else:
                consecutive_errors = 0
                self.stats.packets_received += 1
                if resp.worker_id is not None:
                    self.crash_detector.record_success(resp.worker_id)

            # Check packet cap
            if (
                self.config.max_packets > 0
                and self.stats.packets_sent >= self.config.max_packets
            ):
                logger.info(
                    "Packet limit reached, stopping",
                    packets_sent=self.stats.packets_sent,
                )
                break

    def _handle_response_error(
        self, error: Exception, worker_id: int
    ) -> "object":
        """Classify a transport error and forward to the crash detector."""
        err_str = str(error).lower()
        if "timed out" in err_str or "timeout" in err_str:
            self.stats.timeouts += 1
            return self.crash_detector.record_timeout(worker_id)
        if "refused" in err_str:
            return self.crash_detector.record_connection_failure(
                worker_id, ErrorType.CONNECTION_REFUSED
            )
        if "reset" in err_str:
            return self.crash_detector.record_connection_failure(
                worker_id, ErrorType.CONNECTION_RESET
            )
        # Generic error — treated as a remote-device error
        return self.crash_detector.record_hci_error(worker_id, is_local=False)

    def _should_stop(self) -> bool:
        """Return True if the loop should terminate."""
        return self._interrupted or self.state == SessionState.STOPPED

    async def _shutdown(self) -> None:
        """Gracefully stop the scheduler and record final statistics."""
        self.state = SessionState.STOPPED
        self.stats.stop()
        if self._scheduler is not None:
            await self._scheduler.shutdown()
            self._scheduler = None
        logger.info(
            "FuzzRunner stopped",
            packets_sent=self.stats.packets_sent,
            packets_received=self.stats.packets_received,
            crashes=self.stats.crashes_detected,
            elapsed=f"{self.stats.elapsed_seconds:.1f}s",
        )

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _install_signal_handler(self) -> None:
        """Install SIGINT handler for graceful Ctrl+C interruption.

        On Windows, ``signal.signal`` is used directly because the asyncio
        loop does not support ``add_signal_handler`` on that platform.
        """
        self._original_sigint = signal.getsignal(signal.SIGINT)
        if sys.platform == "win32":
            signal.signal(signal.SIGINT, self._on_interrupt)
        else:  # pragma: no cover
            try:
                loop = asyncio.get_running_loop()
                loop.add_signal_handler(signal.SIGINT, self._on_interrupt_async)
            except (NotImplementedError, RuntimeError):
                signal.signal(signal.SIGINT, self._on_interrupt)

    def _restore_signal_handler(self) -> None:
        """Restore the original SIGINT handler."""
        try:
            if sys.platform == "win32":
                signal.signal(signal.SIGINT, self._original_sigint)
            else:  # pragma: no cover
                try:
                    loop = asyncio.get_running_loop()
                    loop.remove_signal_handler(signal.SIGINT)
                except (NotImplementedError, RuntimeError):
                    signal.signal(signal.SIGINT, self._original_sigint)
        except Exception:  # pragma: no cover
            pass

    def _on_interrupt(self, signum: int, frame: object) -> None:
        """Synchronous SIGINT handler (Windows / fallback)."""
        logger.info("Interrupt received, stopping gracefully")
        self._interrupted = True

    def _on_interrupt_async(self) -> None:
        """Asyncio-compatible SIGINT handler (Linux/macOS)."""
        logger.info("Interrupt received, stopping gracefully")
        self._interrupted = True
