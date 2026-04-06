import json
from pathlib import Path

from sdpfuzz2.domain.models import PacketLogEntry, RunLog
from sdpfuzz2.logging.run_logger import RunLogger


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
