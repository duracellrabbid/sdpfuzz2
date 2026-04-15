"""Continuation-state mutation helpers."""

import random

from sdpfuzz2.fuzzing.mutators import flip_bytes


def mutate_continuation_state(
    seed: bytes,
    *,
    rng: random.Random,
    min_mutations: int = 1,
    max_mutations: int | None = None,
) -> bytes:
    """Mutate continuation-state bytes while preserving original length."""
    if not seed:
        return seed

    return flip_bytes(
        seed,
        rng=rng,
        min_flips=min_mutations,
        max_flips=max_mutations,
    )
