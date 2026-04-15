"""Common mutator helpers used by fuzzing strategies."""

import random


def flip_bytes(
    data: bytes,
    *,
    rng: random.Random,
    min_flips: int = 1,
    max_flips: int | None = None,
) -> bytes:
    """Flip a random set of bytes using XOR masks.

    At least one byte is changed when `data` is non-empty.
    """
    if not data:
        return data

    if min_flips < 1:
        raise ValueError("min_flips must be >= 1")

    upper = len(data) if max_flips is None else max_flips
    if upper < min_flips:
        raise ValueError("max_flips must be >= min_flips")

    flip_count = rng.randint(min_flips, min(upper, len(data)))
    indices = rng.sample(range(len(data)), k=flip_count)

    mutated = bytearray(data)
    for index in indices:
        # Non-zero mask guarantees the chosen byte changes.
        mutated[index] ^= rng.randint(1, 0xFF)

    return bytes(mutated)
