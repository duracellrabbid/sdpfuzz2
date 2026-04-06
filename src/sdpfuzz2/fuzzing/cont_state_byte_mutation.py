"""Continuation-state random-byte mutation strategy placeholder."""

from sdpfuzz2.fuzzing.base import FuzzingStrategy


class ContinuationStateByteMutationStrategy(FuzzingStrategy):
    """Mutates bytes while preserving continuation-state length."""

    def next_packet(self) -> bytes:
        raise NotImplementedError("Implemented in Phase 3")
