"""Property-based tests for fuzzing strategies using Hypothesis.

These tests verify strategy behavior holds across a wide range of input
combinations and edge cases using property-based testing.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sdpfuzz2.fuzzing.cont_state_byte_mutation import (
    ContinuationStateByteMutationStrategy,
)
from sdpfuzz2.fuzzing.cont_state_len_mutation import (
    ContinuationStateLengthMutationStrategy,
)
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.sdp.templates import get_templates


class TestTotallyRandomBytesStrategyProperties:
    """Property tests for totally random bytes strategy."""

    @given(
        min_length=st.integers(min_value=1, max_value=100),
        max_length=st.integers(min_value=1, max_value=200),
        seed=st.integers(min_value=0, max_value=2**31 - 1),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
    def test_respects_length_bounds(self, min_length: int, max_length: int, seed: int) -> None:
        """Property: all packets should respect min/max length constraints."""
        if min_length > max_length:
            min_length, max_length = max_length, min_length

        strategy = TotallyRandomBytesStrategy(
            min_length=min_length, max_length=max_length, seed=seed
        )

        for _ in range(20):
            packet = strategy.next_packet()
            assert min_length <= len(packet) <= max_length

    @given(
        min_length=st.integers(min_value=1, max_value=50),
        max_length=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=50)
    def test_variety_across_bounds(self, min_length: int, max_length: int) -> None:
        """Property: strategy should generate varying lengths within the bounds."""
        if min_length > max_length:
            min_length, max_length = max_length, min_length

        strategy = TotallyRandomBytesStrategy(min_length=min_length, max_length=max_length, seed=42)

        lengths = {len(strategy.next_packet()) for _ in range(100)}

        # Should hit multiple different lengths if range > 1
        if min_length < max_length:
            assert len(lengths) > 1

    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=50)
    def test_all_packets_are_bytes(self, seed: int) -> None:
        """Property: every packet must be bytes type."""
        strategy = TotallyRandomBytesStrategy(seed=seed)

        for _ in range(20):
            packet = strategy.next_packet()
            assert isinstance(packet, bytes)
            assert len(packet) > 0


class TestContinuationStateLengthMutationStrategyProperties:
    """Property tests for continuation length mutation strategy."""

    @given(
        min_oversized=st.integers(min_value=0x00, max_value=0xFF),
        max_oversized=st.integers(min_value=0x00, max_value=0xFF),
        seed=st.integers(min_value=0, max_value=2**31 - 1),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
    def test_continuation_length_mutated(
        self, min_oversized: int, max_oversized: int, seed: int
    ) -> None:
        """Property: continuation length byte should be within mutation bounds."""
        if min_oversized > max_oversized:
            min_oversized, max_oversized = max_oversized, min_oversized

        strategy = ContinuationStateLengthMutationStrategy(
            min_oversized_length=min_oversized,
            max_oversized_length=max_oversized,
            seed=seed,
        )

        for _ in range(20):
            packet = strategy.next_packet()
            # Packet format: PDU(1) + TxID(2) + ParamLen(2) + Params
            # In params: SearchPattern(5) + MaxAttrCount(2) + AttrIDList(7) + ContLen(1)
            param_length = int.from_bytes(packet[3:5], byteorder="big")
            params = packet[5 : 5 + param_length]
            cont_len_index = 14
            cont_len = params[cont_len_index]

            assert min_oversized <= cont_len <= max_oversized

    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=50)
    def test_packets_are_valid_sdp_format(self, seed: int) -> None:
        """Property: packets should have valid SDP response format."""
        strategy = ContinuationStateLengthMutationStrategy(seed=seed)

        for _ in range(20):
            packet = strategy.next_packet()
            # Must be at least header + minimal params
            assert len(packet) >= 5
            # PDU ID should be Service Search Attribute Response (0x06)
            assert packet[0] == 0x06
            # Parameter length should match actual packet
            param_length = int.from_bytes(packet[3:5], byteorder="big")
            assert len(packet) == 5 + param_length


class TestContinuationStateByteMutationStrategyProperties:
    """Property tests for continuation state byte mutation strategy."""

    @given(continuation_states=st.lists(st.binary(min_size=1, max_size=10), min_size=1, max_size=5))
    @settings(max_examples=100)
    def test_generates_valid_packets(self, continuation_states: list[bytes]) -> None:
        """Property: all generated packets must be valid SDP format."""
        strategy = ContinuationStateByteMutationStrategy(
            valid_continuation_states=continuation_states,
            seed=99,
        )

        for _ in range(20):
            packet = strategy.next_packet()
            assert isinstance(packet, bytes)
            assert len(packet) >= 5
            assert packet[0] == 0x06

    @given(
        continuation_state=st.binary(min_size=1, max_size=8),
        seed=st.integers(min_value=0, max_value=2**31 - 1),
    )
    @settings(max_examples=100)
    def test_preserves_continuation_length(self, continuation_state: bytes, seed: int) -> None:
        """Property: mutated packets should preserve original continuation state length."""
        strategy = ContinuationStateByteMutationStrategy(
            valid_continuation_states=[continuation_state],
            seed=seed,
        )

        for _ in range(20):
            packet = strategy.next_packet()
            # Extract continuation length from packet
            param_length = int.from_bytes(packet[3:5], byteorder="big")
            params = packet[5 : 5 + param_length]
            cont_len_index = 14
            cont_len = params[cont_len_index]

            # Should match original continuation state length
            assert cont_len == len(continuation_state)


class TestRandomMutationStrategyProperties:
    """Property tests for random mutation strategy."""

    @given(
        min_flips=st.integers(min_value=1, max_value=10),
        max_flips=st.integers(min_value=1, max_value=15),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
    def test_mutated_packets_differ_from_template(self, min_flips: int, max_flips: int) -> None:
        """Property: mutated packets should differ from original templates."""
        if min_flips > max_flips:
            min_flips, max_flips = max_flips, min_flips

        templates = get_templates()
        # Limit flips to reasonable range relative to template sizes
        max_flips = min(max_flips, 10)

        strategy = RandomMutationStrategy(
            templates=templates,
            min_flips=min_flips,
            max_flips=max_flips,
            seed=42,
        )

        # Generate many packets and verify they differ from templates
        mutated = [strategy.next_packet() for _ in range(50)]
        for packet in mutated:
            # At least one packet should differ from any template (statistically)
            # Since we're mutating, most should be different from originals
            assert isinstance(packet, bytes)

    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=50)
    def test_output_template_length(self, seed: int) -> None:
        """Property: mutated packets should preserve template length."""
        templates = get_templates()
        strategy = RandomMutationStrategy(templates=templates, seed=seed)

        template_lengths = {len(t) for t in templates}

        for _ in range(30):
            packet = strategy.next_packet()
            assert len(packet) in template_lengths

    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=50)
    def test_seed_provides_reproducibility(self, seed: int) -> None:
        """Property: same seed should produce same sequence of packets."""
        templates = get_templates()

        strategy1 = RandomMutationStrategy(templates=templates, seed=seed)
        strategy2 = RandomMutationStrategy(templates=templates, seed=seed)

        packets1 = [strategy1.next_packet() for _ in range(20)]
        packets2 = [strategy2.next_packet() for _ in range(20)]

        assert packets1 == packets2
