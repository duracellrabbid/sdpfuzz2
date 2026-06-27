import asyncio
import time

import pytest

from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.orchestration.scheduler import WorkerScheduler
from sdpfuzz2.orchestration.workers import (
    AsyncRateLimiter,
    FuzzRequest,
    FuzzResponse,
    FuzzWorker,
    WorkerPool,
)


class FakeTransport:
    def __init__(
        self,
        responses: list[bytes] | None = None,
        delay: float = 0.0,
        error_on_send: Exception | None = None,
        error_on_recv: Exception | None = None,
    ) -> None:
        self.responses = responses or []
        self.delay = delay
        self.error_on_send = error_on_send
        self.error_on_recv = error_on_recv
        self.send_count = 0
        self.recv_count = 0
        self.sent_payloads: list[bytes] = []
        self.closed = False

    def send(self, payload: bytes) -> None:
        if self.closed:
            raise RuntimeError("Closed")
        self.send_count += 1
        self.sent_payloads.append(payload)
        if self.error_on_send is not None:
            raise self.error_on_send

    def receive(self, timeout_ms: int) -> bytes:
        if self.closed:
            raise RuntimeError("Closed")
        self.recv_count += 1
        if self.error_on_recv is not None:
            raise self.error_on_recv
        if self.delay > 0:
            time.sleep(self.delay)
        if self.recv_count - 1 < len(self.responses):
            return self.responses[self.recv_count - 1]
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"

    def close(self) -> None:
        self.closed = True


def test_worker_lifecycle_happy_path() -> None:
    async def run_test() -> None:
        transport = FakeTransport(responses=[b"response1"])
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        worker = FuzzWorker(
            worker_id=1,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )

        await input_queue.put(FuzzRequest(packet_index=1, payload=b"request1"))

        # Start worker in background
        task = asyncio.create_task(worker.run())

        # Wait for response in output queue
        resp = await output_queue.get()
        assert resp.packet_index == 1
        assert resp.request_payload == b"request1"
        assert resp.response_payload == b"response1"
        assert resp.error is None
        assert resp.worker_id == 1

        # Stop worker and wait for task termination
        stop_event.set()
        await task

        assert transport.closed is True

    asyncio.run(run_test())


def test_worker_transport_error() -> None:
    async def run_test() -> None:
        transport = FakeTransport(error_on_recv=ValueError("Receive error"))
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        worker = FuzzWorker(
            worker_id=2,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )

        await input_queue.put(FuzzRequest(packet_index=42, payload=b"request2"))

        task = asyncio.create_task(worker.run())
        resp = await output_queue.get()
        assert resp.packet_index == 42
        assert resp.response_payload is None
        assert isinstance(resp.error, ValueError)
        assert "Receive error" in str(resp.error)

        stop_event.set()
        await task
        assert transport.closed is True

    asyncio.run(run_test())


def test_worker_pool_configurable_concurrency() -> None:
    async def run_test() -> None:
        transports: list[FakeTransport] = []

        def transport_factory() -> Transport:
            t = FakeTransport()
            transports.append(t)
            return t

        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        pool = WorkerPool(
            concurrency=3,
            transport_factory=transport_factory,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )

        await pool.start()
        assert len(pool._workers) == 3
        assert len(pool._tasks) == 3
        assert len(transports) == 3

        await pool.shutdown()
        assert all(t.closed for t in transports)

    asyncio.run(run_test())


def test_bounded_queue_and_backpressure() -> None:
    async def run_test() -> None:
        config = RuntimeConfig(concurrency=1, queue_size=2)
        scheduler = WorkerScheduler(config=config, transport_factory=FakeTransport)

        # Do not start the scheduler/workers yet so queue doesn't drain
        assert scheduler.input_queue.maxsize == 2

        await scheduler.submit(b"req1")
        await scheduler.submit(b"req2")

        assert scheduler.input_queue.full() is True

        # Submitting a 3rd request should block (timeout test)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(scheduler.submit(b"req3"), timeout=0.1)

    asyncio.run(run_test())


def test_monotonic_packet_indexing() -> None:
    async def run_test() -> None:
        config = RuntimeConfig(concurrency=1, queue_size=5)
        scheduler = WorkerScheduler(config=config, transport_factory=FakeTransport)

        idx1 = await scheduler.submit(b"a")
        idx2 = await scheduler.submit(b"b")
        idx3 = await scheduler.submit(b"c")

        assert idx1 == 1
        assert idx2 == 2
        assert idx3 == 3

    asyncio.run(run_test())


def test_response_mapping_and_out_of_order() -> None:
    async def run_test() -> None:
        config = RuntimeConfig(concurrency=2, queue_size=5)

        # We can use specific transports
        transports = [
            FakeTransport(responses=[b"resp1"], delay=0.2),  # slower
            FakeTransport(responses=[b"resp2"], delay=0.01),  # faster
        ]
        t_idx = 0

        def transport_factory() -> Transport:
            nonlocal t_idx
            t = transports[t_idx]
            t_idx += 1
            return t

        scheduler = WorkerScheduler(config=config, transport_factory=transport_factory)
        await scheduler.start()

        idx1 = await scheduler.submit(b"req1")
        await asyncio.sleep(0.02)
        idx2 = await scheduler.submit(b"req2")

        # Wait for both responses
        resp2 = await scheduler.get_response(idx2, timeout_seconds=1.0)
        resp1 = await scheduler.get_response(idx1, timeout_seconds=1.0)

        assert resp1.response_payload == b"resp1"
        assert resp2.response_payload == b"resp2"

        await scheduler.shutdown()

    asyncio.run(run_test())


def test_async_rate_limiter() -> None:
    async def run_test() -> None:
        limiter = AsyncRateLimiter(rate_limit=10.0)

        start_time = asyncio.get_running_loop().time()
        for _ in range(5):
            await limiter.acquire()
        end_time = asyncio.get_running_loop().time()

        elapsed = end_time - start_time
        assert elapsed >= 0.35

    asyncio.run(run_test())


def test_worker_delay() -> None:
    async def run_test() -> None:
        transport = FakeTransport(responses=[b"r"])
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        worker = FuzzWorker(
            worker_id=1,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
            delay_ms=200.0,  # 0.2s delay
        )

        await input_queue.put(FuzzRequest(packet_index=1, payload=b"q"))

        start_time = asyncio.get_running_loop().time()
        task = asyncio.create_task(worker.run())
        await output_queue.get()
        end_time = asyncio.get_running_loop().time()

        elapsed = end_time - start_time
        assert elapsed >= 0.18

        stop_event.set()
        await task

    asyncio.run(run_test())


def test_graceful_worker_shutdown_with_timeout() -> None:
    async def run_test() -> None:
        transport = FakeTransport(responses=[b"r"], delay=2.0)

        scheduler = WorkerScheduler(
            config=RuntimeConfig(concurrency=1, response_timeout_ms=5000),
            transport_factory=lambda: transport,
        )
        await scheduler.start()

        idx = await scheduler.submit(b"payload")
        await asyncio.sleep(0.05)

        # Shutdown with a very small timeout. It should cancel the task.
        start_time = asyncio.get_running_loop().time()
        await scheduler.shutdown(timeout_seconds=0.1)
        end_time = asyncio.get_running_loop().time()

        assert end_time - start_time < 0.5

        with pytest.raises(asyncio.CancelledError):
            await scheduler.get_response(idx)

    asyncio.run(run_test())


def test_unconfigured_worker_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        asyncio.run(FuzzWorker().run())


def test_rate_limiter_disabled() -> None:
    async def run_test() -> None:
        limiter = AsyncRateLimiter(rate_limit=0)
        await limiter.acquire()
        assert limiter.last_update is None

    asyncio.run(run_test())


def test_scheduler_unconfigured() -> None:
    with pytest.raises(NotImplementedError):
        asyncio.run(WorkerScheduler().start())


def test_scheduler_submit_stopped() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        scheduler.stop_event.set()
        with pytest.raises(RuntimeError, match="Scheduler is stopped"):
            await scheduler.submit(b"req")

    asyncio.run(run_test())


def test_scheduler_get_response_invalid() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        with pytest.raises(ValueError, match="Packet index 999 not found"):
            await scheduler.get_response(999)

    asyncio.run(run_test())


def test_scheduler_shutdown_not_started() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        await scheduler.shutdown()

    asyncio.run(run_test())


def test_worker_close_transport_error() -> None:
    async def run_test() -> None:
        class BadTransport(FakeTransport):
            def close(self) -> None:
                raise RuntimeError("Failed to close")

        transport = BadTransport()
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        worker = FuzzWorker(
            worker_id=1,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )

        task = asyncio.create_task(worker.run())
        stop_event.set()
        await task

    asyncio.run(run_test())


def test_worker_cancel_during_dequeue() -> None:
    async def run_test() -> None:
        transport = FakeTransport()
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        worker = FuzzWorker(
            worker_id=1,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )

        task = asyncio.create_task(worker.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_test())


def test_scheduler_get_response_cached() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        await scheduler.start()
        idx = await scheduler.submit(b"payload")
        await asyncio.sleep(0.05)
        # First call awaits future and caches response in self.responses
        resp1 = await scheduler.get_response(idx)
        # Second call returns from self.responses (line 90)
        resp2 = await scheduler.get_response(idx)
        assert resp1 is resp2
        await scheduler.shutdown()

    asyncio.run(run_test())


def test_scheduler_shutdown_results_timeout() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        await scheduler.start()

        # Mock results task to run indefinitely
        async def slow_task() -> None:
            await asyncio.sleep(5)

        scheduler._results_task = asyncio.create_task(slow_task())
        # Call shutdown with tiny timeout to trigger TimeoutError branch
        await scheduler.shutdown(timeout_seconds=0.01)

    asyncio.run(run_test())


def test_worker_pool_shutdown_timeout() -> None:
    async def run_test() -> None:
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()
        pool = WorkerPool(
            concurrency=1,
            transport_factory=FakeTransport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
        )
        await pool.start()

        # Mock the worker task to sleep indefinitely
        async def slow_worker() -> None:
            # Append a new task to pool._tasks that is NOT part of the gather,
            # so it's not cancelled by gather.
            pool._tasks.append(asyncio.create_task(asyncio.sleep(5)))
            await asyncio.sleep(5)

        pool._tasks = [asyncio.create_task(slow_worker())]
        # Call shutdown with tiny timeout to trigger TimeoutError branch
        await pool.shutdown(timeout_seconds=0.01)

    asyncio.run(run_test())


def test_rate_limiter_active_in_worker() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(
            config=RuntimeConfig(concurrency=1),
            transport_factory=FakeTransport,
            rate_limit=10,
        )
        await scheduler.start()
        idx = await scheduler.submit(b"payload")
        resp = await scheduler.get_response(idx)
        assert resp.response_payload is not None
        await scheduler.shutdown()

    asyncio.run(run_test())


def test_scheduler_results_task_cancellation() -> None:
    async def run_test() -> None:
        scheduler = WorkerScheduler(transport_factory=FakeTransport)
        await scheduler.start()
        # Allow the results task to start and enter its loop/wait state
        await asyncio.sleep(0.01)
        # Cancel the results task directly to trigger CancelledError branch (scheduler.py:71-72)
        assert scheduler._results_task is not None
        scheduler._results_task.cancel()
        # Allow task loop to run and execute the cancellation cleanup
        await asyncio.sleep(0.01)
        await scheduler.shutdown()

    asyncio.run(run_test())


def test_worker_shutdown_while_delayed() -> None:
    async def run_test() -> None:
        transport = FakeTransport()
        input_queue: asyncio.Queue[FuzzRequest] = asyncio.Queue()
        output_queue: asyncio.Queue[FuzzResponse] = asyncio.Queue()
        stop_event = asyncio.Event()

        # worker with 100ms delay
        worker = FuzzWorker(
            worker_id=1,
            transport=transport,
            input_queue=input_queue,
            output_queue=output_queue,
            stop_event=stop_event,
            delay_ms=100.0,
        )

        task = asyncio.create_task(worker.run())
        # submit a request
        await input_queue.put(FuzzRequest(packet_index=1, payload=b"test"))
        # yield control to let worker dequeue the request and go to sleep/delay
        await asyncio.sleep(0.02)
        # set stop event while worker is in the delay sleep
        stop_event.set()
        # wait for worker to wake up and exit cleanly
        await task
        # check that input queue task was marked done and worker exited
        assert input_queue.empty()

    asyncio.run(run_test())


def test_worker_pool_shutdown_not_started() -> None:
    async def run_test() -> None:
        pool = WorkerPool(
            concurrency=1,
            transport_factory=FakeTransport,
            input_queue=asyncio.Queue(),
            output_queue=asyncio.Queue(),
            stop_event=asyncio.Event(),
        )
        # WorkerPool shutdown when not started (workers.py:213)
        await pool.shutdown()

    asyncio.run(run_test())


def test_scheduler_in_flight_count() -> None:
    async def run_test() -> None:
        from sdpfuzz2.config import RuntimeConfig
        from sdpfuzz2.orchestration.scheduler import WorkerScheduler

        config = RuntimeConfig(concurrency=1, queue_size=10, response_timeout_ms=100)
        scheduler = WorkerScheduler(
            config=config,
            transport_factory=FakeTransport,
        )
        assert scheduler.in_flight_count == 0
        await scheduler.submit(b"\x01")
        assert scheduler.in_flight_count == 1
        await scheduler.shutdown()

    asyncio.run(run_test())
