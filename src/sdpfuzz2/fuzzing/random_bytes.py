"""Totally random bytes fuzzing strategy."""

import random

from sdpfuzz2.fuzzing.base import FuzzingStrategy


class TotallyRandomBytesStrategy(FuzzingStrategy):
    """Generate random payloads with length constrained to a configured range."""

    def __init__(
        self,
        *,
        min_length: int = 16,
        max_length: int = 64,
        seed: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        """Initialize the strategy.

        `seed` provides deterministic output for tests and reproducible fuzzing.
        `rng` is accepted for callers that want to inject an already-configured
        random source.
        """
        if min_length < 1:
            raise ValueError("min_length must be >= 1")
        if max_length < min_length:
            raise ValueError("max_length must be >= min_length")
        if seed is not None and rng is not None:
            raise ValueError("seed and rng are mutually exclusive")

        self._min_length = min_length
        self._max_length = max_length
        self._rng = rng if rng is not None else random.Random(seed)

    def next_packet(self) -> bytes:
        """Return a new random byte string within the configured size bounds."""
        length = self._rng.randint(self._min_length, self._max_length)
        return bytes(self._rng.getrandbits(8) for _ in range(length))
