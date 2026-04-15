"""Random mutation strategy over valid SDP request templates."""

import random

from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.fuzzing.mutators import flip_bytes
from sdpfuzz2.sdp.templates import get_templates


class RandomMutationStrategy(FuzzingStrategy):
    """Generate packet mutations by flipping random bytes in valid templates."""

    def __init__(
        self,
        *,
        templates: list[bytes] | None = None,
        min_flips: int = 1,
        max_flips: int | None = None,
        seed: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        resolved_templates = get_templates() if templates is None else templates
        if not resolved_templates:
            raise ValueError("templates must not be empty")
        if not all(template for template in resolved_templates):
            raise ValueError("templates must contain non-empty packets")
        if seed is not None and rng is not None:
            raise ValueError("seed and rng are mutually exclusive")

        self._templates = list(resolved_templates)
        self._min_flips = min_flips
        self._max_flips = max_flips
        self._rng = rng if rng is not None else random.Random(seed)

    def next_packet(self) -> bytes:
        template = self._rng.choice(self._templates)
        return flip_bytes(
            template,
            rng=self._rng,
            min_flips=self._min_flips,
            max_flips=self._max_flips,
        )
