"""Corpus-mutation fuzzing strategy."""

import random

from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.fuzzing.mutators import flip_bytes
from sdpfuzz2.logging import CorpusManager


class CorpusMutationStrategy(FuzzingStrategy):
    """Fuzzing strategy that mutates packet seeds loaded from the corpus."""

    def __init__(self, corpus_manager: CorpusManager, seed: int | None = None) -> None:
        """Initialize the corpus mutation strategy."""
        self.corpus_manager = corpus_manager
        self.rng = random.Random(seed)

    def next_packet(self) -> bytes:
        """Pick a random packet from a random corpus sequence, mutate it, and return."""
        seqs = self.corpus_manager.list_sequences()
        if not seqs:
            raise ValueError("Corpus is empty, cannot perform corpus-mutation fuzzing.")

        # Pick a random sequence
        seq = self.rng.choice(seqs)
        packets = self.corpus_manager.load_packets(seq["id"])
        if not packets:
            raise ValueError(f"Sequence {seq['id']} has no packets.")

        # Pick a random packet in the sequence
        packet_idx = self.rng.randint(0, len(packets) - 1)
        selected_packet = packets[packet_idx]

        # Apply byte-flip mutations
        return flip_bytes(selected_packet, rng=self.rng)
