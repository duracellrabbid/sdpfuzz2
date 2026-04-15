"""Continuation-state length mutation strategy."""

import random

from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request


class ContinuationStateLengthMutationStrategy(FuzzingStrategy):
    """Generate valid requests with an intentionally oversized continuation length."""

    def __init__(
        self,
        *,
        min_oversized_length: int = 0x80,
        max_oversized_length: int = 0xFF,
        transaction_id_start: int = 1,
        seed: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if not 1 <= transaction_id_start <= 0xFFFF:
            raise ValueError("transaction_id_start must be between 1 and 65535")
        if not 0 <= min_oversized_length <= 0xFF:
            raise ValueError("min_oversized_length must be between 0 and 255")
        if not 0 <= max_oversized_length <= 0xFF:
            raise ValueError("max_oversized_length must be between 0 and 255")
        if max_oversized_length < min_oversized_length:
            raise ValueError("max_oversized_length must be >= min_oversized_length")
        if seed is not None and rng is not None:
            raise ValueError("seed and rng are mutually exclusive")

        self._min_oversized_length = min_oversized_length
        self._max_oversized_length = max_oversized_length
        self._transaction_id = transaction_id_start
        self._rng = rng if rng is not None else random.Random(seed)

    def _next_transaction_id(self) -> int:
        current = self._transaction_id
        self._transaction_id = 1 if self._transaction_id >= 0xFFFF else self._transaction_id + 1
        return current

    def next_packet(self) -> bytes:
        packet = bytearray(
            build_service_search_attribute_request(
                transaction_id=self._next_transaction_id(),
                continuation_state=b"",
            )
        )
        packet[-1] = self._rng.randint(self._min_oversized_length, self._max_oversized_length)
        return bytes(packet)
