from typing import Any, cast

from sdpfuzz2.domain.models import Device, PacketLogEntry, RunLog


def test_device_accepts_valid_mac() -> None:
    device = Device(name="Target", mac_address="AA:BB:CC:DD:EE:FF")

    assert device.mac_address == "AA:BB:CC:DD:EE:FF"


def test_device_rejects_invalid_mac() -> None:
    try:
        Device(name="Target", mac_address="INVALID")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected invalid MAC to raise ValueError")


def test_run_log_supports_required_schema_fields() -> None:
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

    dumped = cast(dict[str, Any], run_log.to_dict())
    assert dumped["device_name"] == "Device"
    assert dumped["logs"][0]["crash"] == 0
