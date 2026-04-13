import pytest

from sdpfuzz2.bluetooth.probe import ProbeResult, SDPProbe
from sdpfuzz2.domain.errors import PacketParseError
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request
from sdpfuzz2.sdp.parser import parse_response


class FakeTransport:
    def __init__(self, responses: list[bytes]) -> None:
        self._responses = responses
        self.sent_packets: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.sent_packets.append(payload)

    def receive(self, timeout_ms: int) -> bytes:
        del timeout_ms
        if not self._responses:
            raise AssertionError("No more fake responses available")
        return self._responses.pop(0)


def _build_response(
    *, transaction_id: int, attribute_payload: bytes, continuation_state: bytes = b""
) -> bytes:
    params = (
        len(attribute_payload).to_bytes(2, byteorder="big")
        + attribute_payload
        + bytes((len(continuation_state),))
        + continuation_state
    )
    return b"\x07" + transaction_id.to_bytes(2, byteorder="big") + len(params).to_bytes(
        2, byteorder="big"
    ) + params


def test_build_service_search_attribute_request_default_fixture() -> None:
    packet = build_service_search_attribute_request()

    assert packet.hex() == "060001000f3503191002ffff35050a0000ffff00"


def test_build_service_search_attribute_request_with_continuation_state() -> None:
    packet = build_service_search_attribute_request(
        transaction_id=2,
        continuation_state=b"\x01\x02\x03",
        max_attribute_byte_count=0x0200,
    )

    assert packet.hex() == "06000200123503191002020035050a0000ffff03010203"


def test_parse_response_extracts_attribute_payload_and_continuation_state() -> None:
    payload = _build_response(
        transaction_id=7,
        attribute_payload=b"\x35\x03\x09\x00\x01",
        continuation_state=b"\xAA\xBB",
    )

    parsed = parse_response(payload)

    assert parsed["transaction_id"] == 7
    assert parsed["attribute_lists_byte_count"] == 5
    assert parsed["attribute_lists"] == b"\x35\x03\x09\x00\x01"
    assert parsed["continuation_state"] == b"\xAA\xBB"
    assert parsed["has_more"] is True


def test_parse_response_rejects_malformed_payloads() -> None:
    with pytest.raises(PacketParseError, match="too short"):
        parse_response(b"\x07\x00")

    with pytest.raises(PacketParseError, match="Unexpected SDP response PDU ID"):
        parse_response(b"\x06\x00\x01\x00\x03\x00\x00\x00")

    with pytest.raises(PacketParseError, match="parameter length mismatch"):
        parse_response(b"\x07\x00\x01\x00\x04\x00\x00\x00")

    truncated_attr = b"\x07\x00\x01\x00\x04\x00\x02\xAA\x00"
    with pytest.raises(PacketParseError, match="Truncated SDP attribute list payload"):
        parse_response(truncated_attr)

    bad_cont_state = b"\x07\x00\x01\x00\x05\x00\x01\xAA\x02\xBB"
    with pytest.raises(PacketParseError, match="continuation state length mismatch"):
        parse_response(bad_cont_state)


def test_probe_collects_paginated_attribute_lists_and_continuation_states() -> None:
    first_page = _build_response(
        transaction_id=1,
        attribute_payload=b"\x35\x02\x09\x00",
        continuation_state=b"\x10\x20",
    )
    second_page = _build_response(
        transaction_id=2,
        attribute_payload=b"\x01\x35\x03\x09\x00\x01",
    )
    transport = FakeTransport([first_page, second_page])

    result = SDPProbe(transport=transport, response_timeout_ms=1200).collect_initial_state()

    assert isinstance(result, ProbeResult)
    assert result.attribute_list_fragments == [b"\x35\x02\x09\x00", b"\x01\x35\x03\x09\x00\x01"]
    assert result.continuation_states == [b"\x10\x20"]
    assert result.full_attribute_list == b"\x35\x02\x09\x00\x01\x35\x03\x09\x00\x01"

    assert transport.sent_packets[0].hex() == "060001000f3503191002ffff35050a0000ffff00"
    assert transport.sent_packets[1].hex() == "06000200113503191002ffff35050a0000ffff021020"
