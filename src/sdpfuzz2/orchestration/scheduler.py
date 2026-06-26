"""Concurrency scheduler."""

import asyncio
from collections.abc import Callable

import structlog

from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.orchestration.workers import FuzzRequest, FuzzResponse, WorkerPool

logger = structlog.get_logger()


class WorkerScheduler:
    """Coordinates bounded queue and worker execution."""

    def __init__(
        self,
        config: RuntimeConfig | None = None,
        transport_factory: Callable[[], Transport] | None = None,
        delay_ms: float = 0.0,
        rate_limit: int = 0,
    ) -> None:
        self.config = config or RuntimeConfig()
        self.transport_factory = transport_factory
        self.delay_ms = delay_ms
        self.rate_limit = rate_limit
        self.input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue(maxsize=self.config.queue_size)
        self.results_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        self.stop_event = asyncio.Event()
        self._next_packet_index = 1
        self.responses: dict[int, FuzzResponse] = {}
        self._futures: dict[int, asyncio.Future[FuzzResponse]] = {}
        self._pool: WorkerPool | None = None
        self._results_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the worker pool and results processing task."""
        if self.transport_factory is None:
            raise NotImplementedError("WorkerScheduler not fully configured")

        self.stop_event.clear()
        self._pool = WorkerPool(
            concurrency=self.config.concurrency,
            transport_factory=self.transport_factory,
            input_queue=self.input_queue,
            output_queue=self.results_queue,
            stop_event=self.stop_event,
            delay_ms=self.delay_ms,
            rate_limit=self.rate_limit,
            response_timeout_ms=self.config.response_timeout_ms,
        )
        await self._pool.start()
        self._results_task = asyncio.create_task(
            self._process_results(), name="SchedulerResultsProcessor"
        )

    async def _process_results(self) -> None:
        while not self.stop_event.is_set() or not self.results_queue.empty():
            try:
                resp = await asyncio.wait_for(self.results_queue.get(), timeout=0.1)
                idx = resp.packet_index
                self.responses[idx] = resp
                fut = self._futures.get(idx)
                if fut and not fut.done():
                    fut.set_result(resp)
                self.results_queue.task_done()
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def submit(self, payload: bytes) -> int:
        """Submit a request payload. Assigns a monotonic packet index and enqueues it.

        Blocks if the input queue is full (providing backpressure).
        Returns the assigned packet index.
        """
        if self.stop_event.is_set():
            raise RuntimeError("Scheduler is stopped")
        idx = self._next_packet_index
        self._next_packet_index += 1
        self._futures[idx] = asyncio.get_running_loop().create_future()
        req = FuzzRequest(packet_index=idx, payload=payload)
        await self.input_queue.put(req)
        return idx

    async def get_response(
        self, packet_index: int, timeout_seconds: float | None = None
    ) -> FuzzResponse:
        """Get the response for a given packet index, waiting if necessary."""
        if packet_index in self.responses:
            return self.responses[packet_index]
        if packet_index not in self._futures:
            raise ValueError(f"Packet index {packet_index} not found")
        fut = self._futures[packet_index]
        if timeout_seconds is not None:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout_seconds)
        return await fut

    @property
    def in_flight_count(self) -> int:
        """Return the number of requests currently in flight (submitted but not completed)."""
        return sum(1 for fut in self._futures.values() if not fut.done())

    async def shutdown(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully shut down the worker pool and results processing task."""
        self.stop_event.set()

        # Set exception/cancel on all pending futures
        for fut in self._futures.values():
            if not fut.done():
                fut.set_exception(asyncio.CancelledError("Scheduler shutdown"))

        if self._pool:
            await self._pool.shutdown(timeout_seconds)

        if self._results_task:
            try:
                async with asyncio.timeout(timeout_seconds):
                    await self._results_task
            except TimeoutError:
                self._results_task.cancel()
                try:
                    await self._results_task
                except asyncio.CancelledError:
                    pass
            self._results_task = None
