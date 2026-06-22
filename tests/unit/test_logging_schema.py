from pydantic import ValidationError

from sdpfuzz2.logging.schema import FuzzingSession, LogEntry, RequestResponseLog


def test_request_response_log_validates_hex_fields() -> None:
    entry = RequestResponseLog(
        request_packet_hex="A1b2",
        response_packet_hex="00FF",
        crash=0,
    )

    assert entry.request_packet_hex == "A1b2"
    assert entry.response_packet_hex == "00FF"


def test_request_response_log_rejects_non_hex_fields() -> None:
    try:
        RequestResponseLog(request_packet_hex="not-hex", response_packet_hex="", crash=0)
    except ValidationError as exc:
        assert "hexadecimal" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for non-hex request payload")


def test_fuzzing_session_validates_mac_address() -> None:
    session = FuzzingSession(
        device_name="Target",
        device_mac_address="00:11:22:33:44:55",
        start_time="2026-06-22T10:00:00Z",
        logs=[
            RequestResponseLog(request_packet_hex="AA", response_packet_hex="BB", crash=0),
        ],
    )

    assert session.device_mac_address == "00:11:22:33:44:55"
    assert session.logs[0].request_packet_hex == "AA"


def test_fuzzing_session_rejects_invalid_mac_address() -> None:
    try:
        FuzzingSession(
            device_name="Target",
            device_mac_address="INVALID",
            start_time="2026-06-22T10:00:00Z",
            logs=[RequestResponseLog(request_packet_hex="AA", response_packet_hex="", crash=0)],
        )
    except ValidationError as exc:
        assert "valid MAC" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for invalid MAC address")


def test_log_entry_is_compatible_alias() -> None:
    entry = LogEntry(request_packet_hex="ABCD", response_packet_hex="", crash=1)

    assert entry.crash == 1
