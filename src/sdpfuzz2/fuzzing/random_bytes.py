"""Totally random bytes strategy placeholder."""

from sdpfuzz2.fuzzing.base import FuzzingStrategy


class TotallyRandomBytesStrategy(FuzzingStrategy):
    """Strategy for generating random SDP-like payloads."""

    def next_packet(self) -> bytes:
        raise NotImplementedError("Implemented in Phase 3")
