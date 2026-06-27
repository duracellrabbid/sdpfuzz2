import json
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from sdpfuzz2.domain.models import PacketLogEntry, RunLog
from sdpfuzz2.logging.run_logger import RunLogger
from sdpfuzz2.logging.schema import FuzzingSession, RequestResponseLog


def test_run_logger_writes_json_file(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)
    run_log = RunLog(
        device_name="Device",
        device_mac_address="00:11:22:33:44:55",
        start_time="2026-04-06 12:00:00 UTC",
        logs=[
            PacketLogEntry(
                request_packet_hex="abcd",
                response_packet_hex="dcba",
                crash=0,
            )
        ],
    )

    logger.write(run_log)

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["device_mac_address"] == "00:11:22:33:44:55"
    assert parsed["logs"][0]["request_packet_hex"] == "abcd"


def test_run_logger_constructor_validates_mac(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    with pytest.raises(ValueError):
        RunLogger(output, device_mac_address="invalid-mac")


def test_run_logger_incremental_logging_and_periodic_flush(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
        flush_interval_seconds=10.0,
        flush_interval_packets=3,
    )

    # Logging 1st packet - shouldn't flush yet
    logger.log_request(packet_index=1, payload=b"\x11\x22")
    assert not output.exists()

    # Logging 2nd packet - shouldn't flush yet
    logger.log_response(packet_index=1, response_payload=b"\x33\x44", crash=0)
    assert not output.exists()

    # Logging 3rd packet - exceeds flush_interval_packets (3 actions/packets logged)
    logger.log_request(packet_index=2, payload=b"\x55\x66")
    assert output.exists()

    # Let's verify file content
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["summary_counters"]["packets_sent"] == 2
    assert parsed["logs"][0]["request_packet_hex"] == "1122"
    assert parsed["logs"][0]["response_packet_hex"] == "3344"
    assert parsed["logs"][1]["request_packet_hex"] == "5566"


def test_run_logger_time_based_flush(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
        flush_interval_seconds=0.05,
        flush_interval_packets=100,
    )

    logger.log_request(packet_index=1, payload=b"\x11")
    assert not output.exists()

    time.sleep(0.06)
    # Logging another action after time elapsed should trigger flush
    logger.log_response(packet_index=1, response_payload=b"\x22", crash=0)
    assert output.exists()


def test_run_logger_out_of_order_sorting(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    # Log request 2, then request 1 (out of order submission/completion)
    logger.log_request(packet_index=2, payload=b"\x22")
    logger.log_request(packet_index=1, payload=b"\x11")

    logger.flush()

    parsed = json.loads(output.read_text(encoding="utf-8"))
    # Verify the logs are sorted by packet_index in the output
    assert parsed["logs"][0]["packet_index"] == 1
    assert parsed["logs"][0]["request_packet_hex"] == "11"
    assert parsed["logs"][1]["packet_index"] == 2
    assert parsed["logs"][1]["request_packet_hex"] == "22"


def test_run_logger_atomic_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    logger.log_request(packet_index=1, payload=b"\x11")

    # Simulate an error during writing to test temp file cleanup
    def mock_write_text(*args: object, **kwargs: object) -> None:
        raise OSError("Mock write error")

    # We patch Path.write_text to raise an error
    monkeypatch.setattr(Path, "write_text", mock_write_text)

    with pytest.raises(OSError, match="Mock write error"):
        logger.flush()

    # The output file should not exist, and no temp file should be left behind
    assert not output.exists()
    temp_files = list(tmp_path.glob("*.tmp"))
    assert len(temp_files) == 0


def test_run_logger_crash_safe_recovery(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    logger.log_request(packet_index=1, payload=b"\x11")
    logger.flush()

    # Verify that the flushed logs are fully valid and parseable
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["device_mac_address"] == "00:11:22:33:44:55"
    assert len(parsed["logs"]) == 1

    # Simulate unexpected termination (new logs added but not flushed)
    logger.log_request(packet_index=2, payload=b"\x22")

    # The file on disk must still be perfectly valid and only contain the first entry
    recovered = FuzzingSession.model_validate_json(output.read_text(encoding="utf-8"))
    assert recovered.device_mac_address == "00:11:22:33:44:55"
    assert len(recovered.logs) == 1
    assert recovered.logs[0].request_packet_hex == "11"


def test_run_logger_metadata_and_finalize(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
        fuzz_mode="random-bytes",
        run_id="run-999",
    )

    logger.log_request(packet_index=1, payload=b"\x11", in_flight_at_send=2, worker_id=1)
    logger.log_response(packet_index=1, response_payload=b"\x99", crash=1, worker_id=1)

    logger.finalize()

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["fuzz_mode"] == "random-bytes"
    assert parsed["run_id"] == "run-999"
    assert "end_time" in parsed
    assert parsed["summary_counters"]["packets_sent"] == 1
    assert parsed["summary_counters"]["packets_received"] == 1
    assert parsed["summary_counters"]["crashes_detected"] == 1
    assert parsed["logs"][0]["in_flight_at_send"] == 2
    assert parsed["logs"][0]["worker_id"] == 1
    assert parsed["logs"][0]["crash"] == 1


def test_run_logger_type_validation_on_write(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    # Invalid hex string payload
    with pytest.raises(ValidationError):
        logger.log_request(packet_index=1, payload="not-hex")


def test_run_logger_atomic_write_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    logger.log_request(packet_index=1, payload=b"\x11")

    # Simulate an error during rename (replace) so the temp file is written but rename fails
    def mock_replace(*args: object, **kwargs: object) -> None:
        raise OSError("Mock replace error")

    monkeypatch.setattr(Path, "replace", mock_replace)

    with pytest.raises(OSError, match="Mock replace error"):
        logger.flush()

    # Verify temp file is cleaned up
    assert not output.exists()
    temp_files = list(tmp_path.glob("*.tmp"))
    assert len(temp_files) == 0


def test_run_logger_write_fuzzing_session_directly(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)
    session = FuzzingSession(
        device_name="Device",
        device_mac_address="00:11:22:33:44:55",
        start_time="2026-04-06T12:00:00Z",
        logs=[RequestResponseLog(request_packet_hex="abcd", response_packet_hex="", crash=0)],
    )

    logger.write(session)

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["device_mac_address"] == "00:11:22:33:44:55"
    assert parsed["logs"][0]["request_packet_hex"] == "abcd"


class DummyClass:
    def __init__(self) -> None:
        from typing import Any

        self.device_name = "Device"
        self.device_mac_address = "00:11:22:33:44:55"
        self.start_time = "2026-04-06 12:00:00 UTC"
        self.logs: list[Any] = [
            {"request_packet_hex": "abcd", "response_packet_hex": "dcba", "crash": 0}
        ]


class DummyLogEntry:
    def __init__(self) -> None:
        self.request_packet_hex = "abcd"
        self.response_packet_hex = "dcba"
        self.crash = 0


def test_run_logger_write_generic_object(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)

    # Test object with __dict__ and log entries that are dicts or have __dict__
    dummy = DummyClass()
    logger.write(dummy)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["device_mac_address"] == "00:11:22:33:44:55"

    # Test logs containing generic objects with __dict__
    dummy.logs = [DummyLogEntry()]
    logger.write(dummy)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["request_packet_hex"] == "abcd"

    # Test logs containing raw dict that needs mapping
    raw_dict = {
        "device_name": "Device",
        "device_mac_address": "00:11:22:33:44:55",
        "start_time": "2026-04-06 12:00:00 UTC",
        "logs": [{"request_packet_hex": "aabb"}],
    }
    logger.write(raw_dict)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["request_packet_hex"] == "aabb"


def test_run_logger_write_with_request_response_log_instances(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)
    raw_dict = {
        "device_name": "Device",
        "device_mac_address": "00:11:22:33:44:55",
        "start_time": "2026-04-06 12:00:00 UTC",
        "logs": [RequestResponseLog(request_packet_hex="aabb", response_packet_hex="cc", crash=0)],
    }
    logger.write(raw_dict)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["request_packet_hex"] == "aabb"


def test_run_logger_log_response_unregistered_packet(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    # Log response directly without preceding request log
    logger.log_response(packet_index=42, response_payload=b"\x99", crash=0)
    logger.flush()

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["packet_index"] == 42
    assert parsed["logs"][0]["request_packet_hex"] == ""
    assert parsed["logs"][0]["response_packet_hex"] == "99"


def test_run_logger_log_response_types_none_and_str(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(
        output,
        device_name="Test Device",
        device_mac_address="00:11:22:33:44:55",
    )

    logger.log_response(packet_index=1, response_payload=None, crash=0)
    logger.log_response(packet_index=2, response_payload="aabb", crash=0)
    logger.flush()

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["response_packet_hex"] == ""
    assert parsed["logs"][1]["response_packet_hex"] == "aabb"


def test_run_logger_custom_start_time(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output, start_time="2026-06-26T12:00:00Z")
    assert logger.start_time == "2026-06-26T12:00:00Z"


class DummyWithToDict:
    def to_dict(self) -> dict[str, object]:
        return {"request_packet_hex": "aabb", "response_packet_hex": "cc", "crash": 0}


def test_run_logger_write_generic_object_with_to_dict_entry(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)
    dummy = DummyClass()
    dummy.logs = [DummyWithToDict()]
    logger.write(dummy)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["request_packet_hex"] == "aabb"


def test_run_logger_write_generic_object_with_dict_castable_entry(tmp_path: Path) -> None:
    output = tmp_path / "run-log.json"
    logger = RunLogger(output)
    dummy = DummyClass()
    # A list of tuples can be cast to a dict using dict()
    dummy.logs = [[("request_packet_hex", "dddd"), ("response_packet_hex", "ee"), ("crash", 0)]]
    logger.write(dummy)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["logs"][0]["request_packet_hex"] == "dddd"
