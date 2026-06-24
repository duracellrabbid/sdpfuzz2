"""Worker lifecycle and execution."""

import asyncio
from dataclasses import dataclass
from typing import Callable

import structlog

from sdpfuzz2.bluetooth.transport import Transport

logger = structlog.get_logger()


@dataclass(frozen=True)
class FuzzRequest:
    """Represents a fuzzing request payload with monotonic index."""

    packet_index: int
    payload: bytes


@dataclass(frozen=True)
class FuzzResponse:
    """Represents the response or error received for a request."""

    packet_index: int
    request_payload: bytes
    response_payload: bytes | None = None
    error: Exception | None = None
    worker_id: int | None = None


class AsyncRateLimiter:
    """Token bucket rate limiter for asyncio."""

    def __init__(self, rate_limit: float) -> None:
        self.rate_limit = rate_limit
        self.max_tokens = 1.0
        self.tokens = 1.0
        self.last_update: float | None = None
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate_limit <= 0:
            return
        async with self.lock:
            now = asyncio.get_running_loop().time()
            if self.last_update is None:
                self.last_update = now
            elapsed = now - self.last_update
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate_limit)
            self.last_update = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            wait_time = (1.0 - self.tokens) / self.rate_limit
            await asyncio.sleep(wait_time)
            self.last_update = asyncio.get_running_loop().time()


class FuzzWorker:
    """Executes packet send/receive cycles."""

    def __init__(
        self,
        worker_id: int = 0,
        transport: Transport | None = None,
        input_queue: asyncio.Queue[FuzzRequest] | None = None,
        output_queue: asyncio.Queue[FuzzResponse] | None = None,
        stop_event: asyncio.Event | None = None,
        delay_ms: float = 0.0,
        rate_limiter: AsyncRateLimiter | None = None,
        response_timeout_ms: int = 1500,
    ) -> None:
        self.worker_id = worker_id
        self.transport = transport
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.stop_event = stop_event
        self.delay_ms = delay_ms
        self.rate_limiter = rate_limiter
        self.response_timeout_ms = response_timeout_ms

    async def run(self) -> None:
        """Run the worker loop."""
        if (
            self.transport is None
            or self.input_queue is None
            or self.output_queue is None
            or self.stop_event is None
        ):
            raise NotImplementedError("FuzzWorker not fully configured")

        logger.info("Worker started", worker_id=self.worker_id)
        try:
            while not self.stop_event.is_set():
                try:
                    # Non-blocking dequeue or wait with timeout to check stop_event
                    req = await asyncio.wait_for(self.input_queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break

                # Apply delay and rate limiting if configured
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                if self.delay_ms > 0:
                    await asyncio.sleep(self.delay_ms / 1000.0)

                if self.stop_event.is_set():
                    self.input_queue.task_done()
                    break

                response_payload = None
                error = None
                logger.debug(
                    "Worker sending packet",
                    worker_id=self.worker_id,
                    packet_index=req.packet_index,
                )
                try:
                    # Execute synchronous I/O operations in an executor thread
                    await asyncio.to_thread(self.transport.send, req.payload)
                    response_payload = await asyncio.to_thread(
                        self.transport.receive, self.response_timeout_ms
                    )
                except Exception as e:
                    error = e
                    logger.error(
                        "Worker transport error",
                        worker_id=self.worker_id,
                        packet_index=req.packet_index,
                        error=str(e),
                    )
                finally:
                    self.input_queue.task_done()

                resp = FuzzResponse(
                    packet_index=req.packet_index,
                    request_payload=req.payload,
                    response_payload=response_payload,
                    error=error,
                    worker_id=self.worker_id,
                )
                await self.output_queue.put(resp)

        finally:
            logger.info("Worker stopping, closing transport", worker_id=self.worker_id)
            try:
                await asyncio.to_thread(self.transport.close)
            except Exception as e:
                logger.warning(
                    "Error closing worker transport",
                    worker_id=self.worker_id,
                    error=str(e),
                )


class WorkerPool:
    """Manages a pool of concurrent FuzzWorker tasks."""

    def __init__(
        self,
        concurrency: int,
        transport_factory: Callable[[], Transport],
        input_queue: asyncio.Queue[FuzzRequest],
        output_queue: asyncio.Queue[FuzzResponse],
        stop_event: asyncio.Event,
        delay_ms: float = 0.0,
        rate_limit: int = 0,
        response_timeout_ms: int = 1500,
    ) -> None:
        self.concurrency = concurrency
        self.transport_factory = transport_factory
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.stop_event = stop_event
        self.delay_ms = delay_ms
        self.rate_limit = rate_limit
        self.response_timeout_ms = response_timeout_ms
        self._workers: list[FuzzWorker] = []
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Start all workers concurrently."""
        rate_limiter = None
        if self.rate_limit > 0:
            rate_limiter = AsyncRateLimiter(float(self.rate_limit))

        for i in range(self.concurrency):
            transport = self.transport_factory()
            worker = FuzzWorker(
                worker_id=i,
                transport=transport,
                input_queue=self.input_queue,
                output_queue=self.output_queue,
                stop_event=self.stop_event,
                delay_ms=self.delay_ms,
                rate_limiter=rate_limiter,
                response_timeout_ms=self.response_timeout_ms,
            )
            self._workers.append(worker)
            task = asyncio.create_task(worker.run(), name=f"FuzzWorker-{i}")
            self._tasks.append(task)

    async def shutdown(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully shut down all workers with a timeout."""
        self.stop_event.set()

        if not self._tasks:
            return

        try:
            async with asyncio.timeout(timeout_seconds):
                await asyncio.gather(*self._tasks, return_exceptions=True)
        except TimeoutError:
            logger.warning("Worker shutdown timed out, cancelling remaining workers")
            for task in self._tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
        finally:
            self._tasks.clear()
            self._workers.clear()
