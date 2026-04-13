"""SDP packet builder helpers."""

PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST = 0x06
_SEARCH_PATTERN_PUBLIC_BROWSE_GROUP = b"\x35\x03\x19\x10\x02"
_ATTRIBUTE_ID_LIST_ALL = b"\x35\x05\x0A\x00\x00\xFF\xFF"


def build_service_search_attribute_request(
    *,
    transaction_id: int = 1,
    continuation_state: bytes = b"",
    max_attribute_byte_count: int = 0xFFFF,
) -> bytes:
    """Build a valid Service Search Attribute request packet.

    The default request asks for all attributes from records matching the
    Public Browse Group root and starts with an empty continuation state.
    """
    if not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("transaction_id must be between 0 and 65535")

    if len(continuation_state) > 0xFF:
        raise ValueError("continuation_state must be at most 255 bytes")

    if not 0 <= max_attribute_byte_count <= 0xFFFF:
        raise ValueError("max_attribute_byte_count must be between 0 and 65535")

    params = (
        _SEARCH_PATTERN_PUBLIC_BROWSE_GROUP
        + max_attribute_byte_count.to_bytes(2, byteorder="big")
        + _ATTRIBUTE_ID_LIST_ALL
        + bytes((len(continuation_state),))
        + continuation_state
    )
    header = (
        bytes((PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST,))
        + transaction_id.to_bytes(2, byteorder="big")
        + len(params).to_bytes(2, byteorder="big")
    )
    return header + params
