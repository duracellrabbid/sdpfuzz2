"""Unit tests for CorpusManager and binary packet serialization."""

from pathlib import Path

import pytest

from sdpfuzz2.logging.corpus_manager import (
    CorpusManager,
    deserialize_sequence,
    serialize_sequence,
)


def test_serialize_deserialize_sequence() -> None:
    """Test serializing and deserializing lists of packets."""
    packets = [b"\x01\x02\x03", b"", b"\xff\xfe"]
    serialized = serialize_sequence(packets)
    deserialized = deserialize_sequence(serialized)
    assert deserialized == packets


def test_deserialize_too_short() -> None:
    """Test deserialization with invalid short data."""
    with pytest.raises(ValueError, match="too short"):
        deserialize_sequence(b"\x00")


def test_deserialize_truncated_length() -> None:
    """Test deserialization with missing length field."""
    # packet count is 2 (0x0002)
    # first packet length 3 (0x0003), payload 3 bytes
    # second packet length field is truncated (only 1 byte instead of 2)
    data = b"\x00\x02\x00\x03\xaa\xbb\xcc\x00"
    with pytest.raises(ValueError, match="missing packet length"):
        deserialize_sequence(data)


def test_deserialize_truncated_payload() -> None:
    """Test deserialization with missing payload bytes."""
    # packet count is 1
    # packet length is 3 (0x0003), but only 2 bytes of payload follow
    data = b"\x00\x01\x00\x03\xaa\xbb"
    with pytest.raises(ValueError, match="missing packet payload"):
        deserialize_sequence(data)


def test_corpus_manager_init(tmp_path: Path) -> None:
    """Test corpus database initialization."""
    manager = CorpusManager(tmp_path)
    assert manager.db_path.exists()


def test_corpus_manager_save_and_list(tmp_path: Path) -> None:
    """Test saving a sequence and listing sequences."""
    manager = CorpusManager(tmp_path)
    packets = [b"\x11\x22", b"\x33"]
    meta = {"notes": "test sequence"}

    seq_id = manager.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=packets,
        metadata=meta,
    )
    assert seq_id is not None

    # Check listing
    seqs = manager.list_sequences()
    assert len(seqs) == 1
    assert seqs[0]["id"] == seq_id
    assert seqs[0]["classification"] == "crash_candidate"
    assert seqs[0]["target_mac"] == "00:11:22:33:44:55"
    assert seqs[0]["packet_count"] == 2
    assert "test sequence" in seqs[0]["metadata"]


def test_corpus_manager_get_and_load(tmp_path: Path) -> None:
    """Test retrieving and loading packet data."""
    manager = CorpusManager(tmp_path)
    packets = [b"\xaa\xbb\xcc"]
    seq_id = manager.save_sequence(
        classification="timeout_candidate",
        target_mac="aa:bb:cc:dd:ee:ff",
        packets=packets,
    )

    # Get sequence metadata
    record = manager.get_sequence(seq_id)
    assert record is not None
    assert record["id"] == seq_id

    # Load packets back
    loaded = manager.load_packets(seq_id)
    assert loaded == packets


def test_corpus_manager_load_failures(tmp_path: Path) -> None:
    """Test load packet failures on missing records or files."""
    manager = CorpusManager(tmp_path)

    # Missing record raises KeyError
    with pytest.raises(KeyError, match="not found"):
        manager.load_packets("nonexistent_id")

    # Missing file raises FileNotFoundError
    seq_id = manager.save_sequence(
        classification="timeout_candidate",
        target_mac="aa:bb:cc:dd:ee:ff",
        packets=[b"\x11"],
    )
    # Manually delete the binary file
    record = manager.get_sequence(seq_id)
    assert record is not None
    Path(record["file_path"]).unlink()

    with pytest.raises(FileNotFoundError, match="Binary sequence file not found"):
        manager.load_packets(seq_id)


def test_corpus_manager_delete_sequence(tmp_path: Path) -> None:
    """Test sequence deletion."""
    manager = CorpusManager(tmp_path)
    seq_id = manager.save_sequence(
        classification="crash_candidate",
        target_mac="00:11:22:33:44:55",
        packets=[b"\x11\x22"],
    )

    record = manager.get_sequence(seq_id)
    assert record is not None
    bin_file = Path(record["file_path"])
    assert bin_file.exists()

    manager.delete_sequence(seq_id)
    assert not bin_file.exists()
    assert manager.get_sequence(seq_id) is None


def test_corpus_manager_delete_nonexistent(tmp_path: Path) -> None:
    """Test deleting non-existent sequence does not crash."""
    manager = CorpusManager(tmp_path)
    # Should complete without error
    manager.delete_sequence("nonexistent_id")


def test_corpus_manager_relative_path_fallback(tmp_path: Path) -> None:
    """Test relative path fallback in load and delete operations."""
    import sqlite3

    manager = CorpusManager(tmp_path)
    with sqlite3.connect(manager.db_path) as conn:
        conn.execute(
            "INSERT INTO sequences VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("rel_id", "crash_candidate", "00:11:22:33:44:55", "timestamp", 1, "rel_id.bin", None),
        )
    bin_file = tmp_path / "rel_id.bin"
    bin_file.write_bytes(serialize_sequence([b"hello"]))

    assert manager.load_packets("rel_id") == [b"hello"]

    deleted_records, deleted_files = manager.clean_corpus()
    assert deleted_records == 0
    assert deleted_files == 0

    manager.delete_sequence("rel_id")
    assert not bin_file.exists()


def test_corpus_manager_delete_unlink_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test delete_sequence when file unlinking raises OSError."""
    manager = CorpusManager(tmp_path)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"packet"])

    def mock_unlink(self: Path) -> None:
        raise OSError("Permission denied")

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    manager.delete_sequence(seq_id)


def test_corpus_manager_clean_corpus(tmp_path: Path) -> None:
    """Test clean_corpus removes orphaned records and files."""
    manager = CorpusManager(tmp_path)

    # 1. Valid record and file (should remain untouched)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"valid"])

    # 2. Orphan record (DB record exists, but file is missing)
    import sqlite3

    with sqlite3.connect(manager.db_path) as conn:
        conn.execute(
            "INSERT INTO sequences VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "orphan_rec",
                "crash_candidate",
                "00:11:22:33:44:55",
                "time",
                1,
                "orphan_rec.bin",
                None,
            ),
        )

    # 3. Orphan file (File exists, but no DB record)
    orphan_file = tmp_path / "orphan_file.bin"
    orphan_file.write_bytes(serialize_sequence([b"orphan"]))

    # Run clean
    deleted_records, deleted_files = manager.clean_corpus()

    assert deleted_records == 1
    assert deleted_files == 1

    # Check that valid remains
    assert manager.get_sequence(seq_id) is not None
    # Check that orphan record is deleted
    assert manager.get_sequence("orphan_rec") is None
    # Check that orphan file is deleted
    assert not orphan_file.exists()


def test_corpus_manager_clean_corpus_unlink_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test clean_corpus handles unlink OSError gracefully."""
    manager = CorpusManager(tmp_path)
    orphan_file = tmp_path / "orphan_file.bin"
    orphan_file.write_bytes(serialize_sequence([b"orphan"]))

    def mock_unlink(self: Path) -> None:
        raise OSError("Permission denied")

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    deleted_records, deleted_files = manager.clean_corpus()
    assert deleted_files == 0
