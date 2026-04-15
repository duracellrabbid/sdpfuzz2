from collections.abc import Callable

from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.fuzzing.cont_state_byte_mutation import ContinuationStateByteMutationStrategy
from sdpfuzz2.fuzzing.cont_state_len_mutation import ContinuationStateLengthMutationStrategy
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.sdp.templates import get_templates

StrategyFactory = Callable[[int], FuzzingStrategy]


def _assert_strategy_outputs_bytes(strategy: FuzzingStrategy) -> None:
    packet = strategy.next_packet()
    assert isinstance(packet, bytes)


def _continuation_len_field(packet: bytes) -> int:
    parameter_length = int.from_bytes(packet[3:5], byteorder="big")
    params = packet[5 : 5 + parameter_length]
    # ServiceSearchAttribute params are fixed up to continuation length byte:
    # search_pattern(5) + max_attribute_count(2) + attr_id_list(7)
    continuation_len_index = 14
    return params[continuation_len_index]


def _all_strategy_factories() -> list[StrategyFactory]:
    return [
        lambda seed: TotallyRandomBytesStrategy(min_length=16, max_length=20, seed=seed),
        lambda seed: ContinuationStateLengthMutationStrategy(seed=seed),
        lambda seed: ContinuationStateByteMutationStrategy(
            valid_continuation_states=[b"\xAA\xBB", b"\x10\x20\x30"],
            seed=seed,
        ),
        lambda seed: RandomMutationStrategy(seed=seed),
    ]


def test_all_strategy_outputs_use_bytes_contract() -> None:
    for factory in _all_strategy_factories():
        strategy = factory(101)
        _assert_strategy_outputs_bytes(strategy)


def test_all_strategies_are_deterministic_with_seed() -> None:
    for factory in _all_strategy_factories():
        first = factory(123)
        second = factory(123)

        first_packets = [first.next_packet() for _ in range(10)]
        second_packets = [second.next_packet() for _ in range(10)]

        assert first_packets == second_packets


def test_totally_random_bytes_strategy_mode_constraints() -> None:
    strategy = TotallyRandomBytesStrategy(min_length=16, max_length=18, seed=7)

    lengths = [len(strategy.next_packet()) for _ in range(100)]

    assert all(16 <= length <= 18 for length in lengths)
    assert {16, 17, 18}.issubset(set(lengths))


def test_continuation_state_length_mutation_mode_constraints() -> None:
    strategy = ContinuationStateLengthMutationStrategy(
        min_oversized_length=0xF0,
        max_oversized_length=0xF0,
        seed=11,
    )

    packet = strategy.next_packet()

    assert packet[0] == 0x06
    assert _continuation_len_field(packet) == 0xF0


def test_continuation_state_byte_mutation_mode_constraints() -> None:
    seed_state = b"\x01\x02\x03\x04"
    strategy = ContinuationStateByteMutationStrategy(
        valid_continuation_states=[seed_state],
        seed=99,
    )

    packet = strategy.next_packet()
    continuation_length = _continuation_len_field(packet)
    continuation_bytes = packet[-continuation_length:]

    assert packet[0] == 0x06
    assert continuation_length == len(seed_state)
    assert continuation_bytes != seed_state


def test_random_mutation_mode_constraints() -> None:
    templates = get_templates()
    strategy = RandomMutationStrategy(templates=templates, seed=2024)

    packet = strategy.next_packet()

    assert len(packet) in {len(template) for template in templates}
    assert packet not in templates


def test_totally_random_bytes_strategy_outputs_bytes() -> None:
    strategy = TotallyRandomBytesStrategy()

    _assert_strategy_outputs_bytes(strategy)
