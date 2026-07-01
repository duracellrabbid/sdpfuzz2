"""Unit tests for ReplayController and CorpusMutationStrategy."""

from pathlib import Path

import pytest

from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.fuzzing.corpus_mutation import CorpusMutationStrategy
from sdpfuzz2.logging.corpus_manager import CorpusManager
from sdpfuzz2.orchestration.replay import ReplayController


class FakeReplayTransport(Transport):
    """Fake transport for testing replay."""

    def __init__(self, fail_on_send: bool = False, fail_on_recv: bool = False) -> None:
        self.sent: list[bytes] = []
        self.closed = False
        self.fail_on_send = fail_on_send
        self.fail_on_recv = fail_on_recv

    def send(self, payload: bytes) -> None:
        if self.fail_on_send:
            raise RuntimeError("Send failure")
        self.sent.append(payload)

    def receive(self, timeout_ms: int) -> bytes:
        if self.fail_on_recv:
            raise RuntimeError("Receive failure")
        return b"\x00"

    def close(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_replay_controller_success(tmp_path: Path) -> None:
    """Test replay controller successful sequence execution."""
    corpus = CorpusManager(tmp_path)
    seq_id = corpus.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"pkt1", b"pkt2"],
    )

    transport = FakeReplayTransport()
    controller = ReplayController(
        corpus_manager=corpus,
        transport_factory_builder=lambda mac: lambda: transport,
    )

    # Replay should succeed (no crashes/timeouts) -> returns False
    result = await controller.replay(seq_id, target_mac="aa:bb:cc:dd:ee:ff")
    assert result is False
    assert transport.sent == [b"pkt1", b"pkt2"]
    assert transport.closed is True


@pytest.mark.anyio
async def test_replay_controller_failure_on_send(tmp_path: Path) -> None:
    """Test replay controller handles transport errors on send."""
    corpus = CorpusManager(tmp_path)
    seq_id = corpus.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"pkt1"],
    )

    transport = FakeReplayTransport(fail_on_send=True)
    controller = ReplayController(
        corpus_manager=corpus,
        transport_factory_builder=lambda mac: lambda: transport,
    )

    # Replay should detect failure -> returns True
    result = await controller.replay(seq_id, target_mac="aa:bb:cc:dd:ee:ff")
    assert result is True
    assert transport.closed is True


@pytest.mark.anyio
async def test_replay_controller_failure_on_recv(tmp_path: Path) -> None:
    """Test replay controller handles transport errors on receive."""
    corpus = CorpusManager(tmp_path)
    seq_id = corpus.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"pkt1"],
    )

    transport = FakeReplayTransport(fail_on_recv=True)
    controller = ReplayController(
        corpus_manager=corpus,
        transport_factory_builder=lambda mac: lambda: transport,
    )

    result = await controller.replay(seq_id, target_mac="aa:bb:cc:dd:ee:ff")
    assert result is True
    assert transport.closed is True


@pytest.mark.anyio
async def test_replay_controller_loops(tmp_path: Path) -> None:
    """Test replay controller loop parameter repeats packets."""
    corpus = CorpusManager(tmp_path)
    seq_id = corpus.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"pkt1"],
    )

    sent_count = 0

    class CountingTransport(FakeReplayTransport):
        def send(self, payload: bytes) -> None:
            nonlocal sent_count
            sent_count += 1
            super().send(payload)

    controller = ReplayController(
        corpus_manager=corpus,
        transport_factory_builder=lambda mac: lambda: CountingTransport(),
    )

    result = await controller.replay(
        seq_id, target_mac="aa:bb:cc:dd:ee:ff", loop_count=3, delay_ms=1.0
    )
    assert result is False
    assert sent_count == 3


@pytest.mark.anyio
async def test_replay_empty_sequence_raises(tmp_path: Path) -> None:
    """Test replay raises error when sequence has no packets."""
    corpus = CorpusManager(tmp_path)
    # Manually register an empty sequence in the database
    import sqlite3

    with sqlite3.connect(corpus.db_path) as conn:
        conn.execute(
            "INSERT INTO sequences VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("empty_seq", "crash_candidate", "00:11:22:33:44:55", "time", 0, "empty_seq.bin", None),
        )
    # Create empty binary file
    bin_file = tmp_path / "empty_seq.bin"
    from sdpfuzz2.logging.corpus_manager import serialize_sequence

    bin_file.write_bytes(serialize_sequence([]))

    controller = ReplayController(corpus)
    with pytest.raises(ValueError, match="no packets to replay"):
        await controller.replay("empty_seq", target_mac="00:11:22:33:44:55")


def test_corpus_mutation_strategy_success(tmp_path: Path) -> None:
    """Test CorpusMutationStrategy picking and mutating a packet."""
    corpus = CorpusManager(tmp_path)
    corpus.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"abcdefgh"])

    strategy = CorpusMutationStrategy(corpus, seed=42)
    mutated = strategy.next_packet()
    assert mutated != b"abcdefgh"
    assert len(mutated) == 8


def test_corpus_mutation_strategy_empty_corpus(tmp_path: Path) -> None:
    """Test CorpusMutationStrategy raises error when corpus is empty."""
    corpus = CorpusManager(tmp_path)
    strategy = CorpusMutationStrategy(corpus)
    with pytest.raises(ValueError, match="Corpus is empty"):
        strategy.next_packet()


def test_corpus_mutation_strategy_empty_sequence_packets(tmp_path: Path) -> None:
    """Test CorpusMutationStrategy raises error if chosen sequence has no packets."""
    corpus = CorpusManager(tmp_path)
    import sqlite3

    with sqlite3.connect(corpus.db_path) as conn:
        conn.execute(
            "INSERT INTO sequences VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("empty_seq", "crash_candidate", "00:11:22:33:44:55", "time", 0, "empty_seq.bin", None),
        )
    bin_file = tmp_path / "empty_seq.bin"
    from sdpfuzz2.logging.corpus_manager import serialize_sequence

    bin_file.write_bytes(serialize_sequence([]))

    strategy = CorpusMutationStrategy(corpus)
    with pytest.raises(ValueError, match="has no packets"):
        strategy.next_packet()


@pytest.mark.anyio
async def test_replay_controller_close_failure(tmp_path: Path) -> None:
    """Test replay controller when transport.close raises an exception."""
    corpus = CorpusManager(tmp_path)
    seq_id = corpus.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"pkt1"],
    )

    class FailingCloseTransport(FakeReplayTransport):
        def close(self) -> None:
            raise RuntimeError("Close failed")

    transport = FailingCloseTransport()
    controller = ReplayController(
        corpus_manager=corpus,
        transport_factory_builder=lambda mac: lambda: transport,
    )

    result = await controller.replay(seq_id, target_mac="aa:bb:cc:dd:ee:ff")
    assert result is False
