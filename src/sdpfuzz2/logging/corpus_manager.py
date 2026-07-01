"""Corpus manager for storing and replaying packet sequences."""

import datetime
import json
import sqlite3
import struct
import uuid
from pathlib import Path
from typing import Any


def serialize_sequence(packets: list[bytes]) -> bytes:
    """Serialize a list of packet payloads using length-prefixed format."""
    data = struct.pack(">H", len(packets))
    for p in packets:
        data += struct.pack(">H", len(p))
        data += p
    return data


def deserialize_sequence(data: bytes) -> list[bytes]:
    """Deserialize a length-prefixed binary sequence into a list of packet payloads."""
    if len(data) < 2:
        raise ValueError("Invalid sequence data: too short")
    packet_count = struct.unpack(">H", data[0:2])[0]
    packets = []
    offset = 2
    for _ in range(packet_count):
        if offset + 2 > len(data):
            raise ValueError("Truncated sequence data: missing packet length")
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        if offset + length > len(data):
            raise ValueError("Truncated sequence data: missing packet payload")
        packets.append(data[offset : offset + length])
        offset += length
    return packets


class CorpusManager:
    """Manages index database (corpus.db) and raw packet sequences (.bin files)."""

    def __init__(self, base_dir: Path | str = "corpus") -> None:
        """Initialize the corpus manager, ensuring database and directories exist."""
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "corpus.db"
        self._init_db()

    def _init_db(self) -> None:
        """Create the sequences table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sequences (
                    id TEXT PRIMARY KEY,
                    classification TEXT NOT NULL,
                    target_mac TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    metadata TEXT
                )
            """)

    def save_sequence(
        self,
        classification: str,
        target_mac: str,
        packets: list[bytes],
        metadata: dict[str, Any] | None = None,
        seq_id: str | None = None,
    ) -> str:
        """Save raw packets to a .bin file and register them in SQLite index."""
        if seq_id is None:
            seq_id = uuid.uuid4().hex

        serialized = serialize_sequence(packets)
        bin_file = self.base_dir / f"{seq_id}.bin"
        bin_file.write_bytes(serialized)

        timestamp = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        metadata_json = json.dumps(metadata) if metadata is not None else None
        file_path_str = str(bin_file)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sequences (
                    id, classification, target_mac, timestamp, packet_count, file_path, metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    seq_id,
                    classification,
                    target_mac,
                    timestamp,
                    len(packets),
                    file_path_str,
                    metadata_json,
                ),
            )
        return seq_id

    def list_sequences(self) -> list[dict[str, Any]]:
        """List all registered sequences from SQLite index."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM sequences ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_sequence(self, seq_id: str) -> dict[str, Any] | None:
        """Get sequence metadata record by its ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM sequences WHERE id = ?", (seq_id,))
            row = cursor.fetchone()
            return dict(row) if row is not None else None

    def load_packets(self, seq_id: str) -> list[bytes]:
        """Load and deserialize packets for a given sequence ID."""
        record = self.get_sequence(seq_id)
        if not record:
            raise KeyError(f"Sequence with ID {seq_id} not found in database index")

        file_path = Path(record["file_path"])
        if not file_path.exists() and not file_path.is_absolute():
            file_path = self.base_dir / file_path.name

        if not file_path.exists():
            raise FileNotFoundError(f"Binary sequence file not found: {file_path}")

        return deserialize_sequence(file_path.read_bytes())

    def delete_sequence(self, seq_id: str) -> None:
        """Delete sequence record and its corresponding .bin file."""
        record = self.get_sequence(seq_id)
        if record:
            file_path = Path(record["file_path"])
            if not file_path.exists() and not file_path.is_absolute():
                file_path = self.base_dir / file_path.name
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM sequences WHERE id = ?", (seq_id,))

    def clean_corpus(self) -> tuple[int, int]:
        """Synchronize the database index and disk, removing orphaned items."""
        deleted_records = 0
        deleted_files = 0

        # 1. Clean orphaned DB records where the file doesn't exist
        records = self.list_sequences()
        for rec in records:
            file_path = Path(rec["file_path"])
            if not file_path.exists() and not file_path.is_absolute():
                file_path = self.base_dir / file_path.name

            if not file_path.exists():
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("DELETE FROM sequences WHERE id = ?", (rec["id"],))
                deleted_records += 1

        # 2. Clean orphaned .bin files in base_dir where there is no DB record
        valid_paths = set()
        for rec in self.list_sequences():
            file_path = Path(rec["file_path"])
            if not file_path.exists() and not file_path.is_absolute():
                file_path = self.base_dir / file_path.name
            valid_paths.add(file_path.resolve())

        # Scan base_dir for *.bin files
        for p in self.base_dir.glob("*.bin"):
            if p.resolve() not in valid_paths:
                try:
                    p.unlink()
                    deleted_files += 1
                except OSError:
                    pass

        return deleted_records, deleted_files
