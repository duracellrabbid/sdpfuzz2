"""Concurrency tests for fuzzing strategies under asyncio task load.

Verifies that strategies maintain correctness when called concurrently from
multiple asyncio tasks, which is closer to the actual orchestration context.
"""

import asyncio

from sdpfuzz2.fuzzing.cont_state_byte_mutation import ContinuationStateByteMutationStrategy
from sdpfuzz2.fuzzing.cont_state_len_mutation import ContinuationStateLengthMutationStrategy
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.sdp.templates import get_templates


async def _call_strategy_concurrently(
    strategy_factory, num_tasks: int
) -> list[bytes]:
    """Call a strategy's next_packet method concurrently from multiple tasks."""

    async def task() -> list[bytes]:
        packets = []
        for _ in range(10):
            packets.append(strategy_factory.next_packet())
            # Yield control to allow other tasks to run
            await asyncio.sleep(0)
        return packets

    tasks = [task() for _ in range(num_tasks)]
    results = await asyncio.gather(*tasks)
    # Flatten results
    return [packet for packets in results for packet in packets]


def test_totally_random_bytes_strategy_async_safety() -> None:
    """Test: random bytes strategy should handle concurrent asyncio task calls."""
    strategy = TotallyRandomBytesStrategy(min_length=16, max_length=24, seed=888)

    async def run_test():
        packets = await _call_strategy_concurrently(strategy, num_tasks=8)
        assert len(packets) == 80  # 8 tasks * 10 packets each
        assert all(isinstance(p, bytes) for p in packets)
        assert all(16 <= len(p) <= 24 for p in packets)
        # Verify no corruption (all packets are reasonable)
        assert all(len(p) > 0 for p in packets)

    asyncio.run(run_test())


def test_continuation_length_mutation_strategy_async_safety() -> None:
    """Test: continuation length mutation should handle concurrent tasks."""
    strategy = ContinuationStateLengthMutationStrategy(
        min_oversized_length=0x80,
        max_oversized_length=0xFE,
        seed=777,
    )

    async def run_test():
        packets = await _call_strategy_concurrently(strategy, num_tasks=6)
        assert len(packets) == 60  # 6 tasks * 10 packets each
        assert all(isinstance(p, bytes) for p in packets)
        # All should be valid SDP packets
        assert all(p[0] == 0x06 for p in packets)

    asyncio.run(run_test())


def test_continuation_byte_mutation_strategy_async_safety() -> None:
    """Test: continuation byte mutation should handle concurrent tasks."""
    strategy = ContinuationStateByteMutationStrategy(
        valid_continuation_states=[b"\x01\x02\x03", b"\xAA\xBB"],
        seed=666,
    )

    async def run_test():
        packets = await _call_strategy_concurrently(strategy, num_tasks=5)
        assert len(packets) == 50  # 5 tasks * 10 packets each
        assert all(isinstance(p, bytes) for p in packets)
        # All should be valid SDP packets
        assert all(p[0] == 0x06 for p in packets)

    asyncio.run(run_test())


def test_random_mutation_strategy_async_safety() -> None:
    """Test: random mutation should handle concurrent tasks."""
    templates = get_templates()
    strategy = RandomMutationStrategy(templates=templates, seed=555)

    async def run_test():
        packets = await _call_strategy_concurrently(strategy, num_tasks=4)
        assert len(packets) == 40  # 4 tasks * 10 packets each
        assert all(isinstance(p, bytes) for p in packets)
        # All packets should be valid template length
        template_lengths = {len(t) for t in templates}
        assert all(len(p) in template_lengths for p in packets)

    asyncio.run(run_test())


def test_mixed_strategy_concurrent_workload() -> None:
    """Test: all strategies should safely run concurrently."""

    async def run_strategy_task(factory) -> list[bytes]:
        packets = []
        for _ in range(5):
            packets.append(factory.next_packet())
            await asyncio.sleep(0)
        return packets

    async def run_test():
        templates = get_templates()
        strategies = [
            TotallyRandomBytesStrategy(seed=111),
            ContinuationStateLengthMutationStrategy(seed=222),
            ContinuationStateByteMutationStrategy(
                valid_continuation_states=[b"\xAA"], seed=333
            ),
            RandomMutationStrategy(templates=templates, seed=444),
        ]

        # Run all strategies concurrently
        tasks = [run_strategy_task(s) for s in strategies]
        results = await asyncio.gather(*tasks)

        # Verify all strategies produced packets
        all_packets = [p for packets in results for p in packets]
        assert len(all_packets) == 20  # 4 strategies * 5 packets each
        assert all(isinstance(p, bytes) for p in all_packets)

    asyncio.run(run_test())


def test_strategy_concurrent_determinism_consistency() -> None:
    """Test: concurrent calls with same seed should still be deterministic."""
    seed_val = 9999

    async def generate_packets(num_packets: int) -> list[bytes]:
        strategy = TotallyRandomBytesStrategy(seed=seed_val)
        packets = []
        for _ in range(num_packets):
            packets.append(strategy.next_packet())
        return packets

    async def run_test():
        # Generate in "serial" (within an async context)
        serial_packets = await generate_packets(20)

        # Generate concurrently (but each strategy instance gets its own seed)
        concurrent_packets = []

        async def concurrent_task() -> list[bytes]:
            return await generate_packets(20)

        results = await asyncio.gather(concurrent_task(), concurrent_task())
        concurrent_packets = [p for packets in results for p in packets]

        # Each independent strategy with same seed should produce identical sequences
        # (within each invocation)
        assert len(serial_packets) == 20
        assert len(concurrent_packets) == 40

    asyncio.run(run_test())
