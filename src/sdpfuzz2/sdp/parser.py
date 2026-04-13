"""SDP response parser helpers."""

from sdpfuzz2.domain.errors import PacketParseError

PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE = 0x07


def parse_response(payload: bytes) -> dict[str, object]:
    """Parse a Service Search Attribute response payload into normalized fields."""
    if len(payload) < 5:
        raise PacketParseError("SDP response too short for header")

    pdu_id = payload[0]
    if pdu_id != PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE:
        raise PacketParseError(f"Unexpected SDP response PDU ID: 0x{pdu_id:02X}")

    transaction_id = int.from_bytes(payload[1:3], byteorder="big")
    parameter_length = int.from_bytes(payload[3:5], byteorder="big")

    if len(payload) != 5 + parameter_length:
        raise PacketParseError("SDP response parameter length mismatch")

    params = payload[5:]
    if len(params) < 3:
        raise PacketParseError("SDP response too short for attribute list and continuation state")

    attribute_lists_byte_count = int.from_bytes(params[0:2], byteorder="big")
    expected_min = 2 + attribute_lists_byte_count + 1
    if len(params) < expected_min:
        raise PacketParseError("Truncated SDP attribute list payload")

    cursor = 2
    attribute_lists = params[cursor : cursor + attribute_lists_byte_count]
    cursor += attribute_lists_byte_count

    continuation_state_len = params[cursor]
    cursor += 1

    if len(params) != cursor + continuation_state_len:
        raise PacketParseError("SDP continuation state length mismatch")

    continuation_state = params[cursor : cursor + continuation_state_len]
    return {
        "pdu_id": pdu_id,
        "transaction_id": transaction_id,
        "parameter_length": parameter_length,
        "attribute_lists_byte_count": attribute_lists_byte_count,
        "attribute_lists": attribute_lists,
        "continuation_state": continuation_state,
        "has_more": continuation_state_len > 0,
    }
