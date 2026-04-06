"""Base strategy contract for fuzzing modes."""

from abc import ABC, abstractmethod


class FuzzingStrategy(ABC):
    """Interface for producing fuzzing packets."""

    @abstractmethod
    def next_packet(self) -> bytes:
        """Produce the next packet to send."""
