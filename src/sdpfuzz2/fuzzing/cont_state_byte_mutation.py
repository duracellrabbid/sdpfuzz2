"""Continuation-state random-byte mutation strategy."""

import random

from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.sdp.continuation import mutate_continuation_state
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request


class ContinuationStateByteMutationStrategy(FuzzingStrategy):
    """Mutate valid continuation-state bytes while preserving continuation length."""

    def __init__(
        self,
        *,
        valid_continuation_states: list[bytes],
        transaction_id_start: int = 1,
        seed: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if not valid_continuation_states:
            raise ValueError("valid_continuation_states must not be empty")
        if not all(state for state in valid_continuation_states):
            raise ValueError("valid_continuation_states must contain non-empty states")
        if not 1 <= transaction_id_start <= 0xFFFF:
            raise ValueError("transaction_id_start must be between 1 and 65535")
        if seed is not None and rng is not None:
            raise ValueError("seed and rng are mutually exclusive")

        self._valid_continuation_states = list(valid_continuation_states)
        self._transaction_id = transaction_id_start
        self._rng = rng if rng is not None else random.Random(seed)

    def _next_transaction_id(self) -> int:
        current = self._transaction_id
        self._transaction_id = 1 if self._transaction_id >= 0xFFFF else self._transaction_id + 1
        return current

    def next_packet(self) -> bytes:
        seed_state = self._rng.choice(self._valid_continuation_states)
        mutated_state = mutate_continuation_state(seed_state, rng=self._rng)
        return build_service_search_attribute_request(
            transaction_id=self._next_transaction_id(),
            continuation_state=mutated_state,
        )
