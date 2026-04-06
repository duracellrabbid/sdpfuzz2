"""Continuation-state length mutation strategy placeholder."""

from sdpfuzz2.fuzzing.base import FuzzingStrategy


class ContinuationStateLengthMutationStrategy(FuzzingStrategy):
    """Mutates continuation-state length with oversized values."""

    def next_packet(self) -> bytes:
        raise NotImplementedError("Implemented in Phase 3")
