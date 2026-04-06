"""Random mutation strategy placeholder."""

from sdpfuzz2.fuzzing.base import FuzzingStrategy


class RandomMutationStrategy(FuzzingStrategy):
    """Mutates valid SDP request templates."""

    def next_packet(self) -> bytes:
        raise NotImplementedError("Implemented in Phase 3")
