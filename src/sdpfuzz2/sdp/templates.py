"""Valid SDP request templates used by mutation strategies."""

from sdpfuzz2.sdp.packet_builder import (
    UUID_PUBLIC_BROWSE_GROUP,
    ATTR_RANGE_ALL,
    build_attribute_id_list,
    build_service_search_attribute_request,
    build_service_search_pattern,
)


def _build_service_search_request(transaction_id: int = 1) -> bytes:
    service_search_pattern = build_service_search_pattern([UUID_PUBLIC_BROWSE_GROUP])
    maximum_service_record_count = (1).to_bytes(2, byteorder="big")
    continuation_state = b"\x00"
    params = service_search_pattern + maximum_service_record_count + continuation_state
    return b"\x02" + transaction_id.to_bytes(2, byteorder="big") + len(params).to_bytes(
        2, byteorder="big"
    ) + params


def _build_service_attribute_request(transaction_id: int = 1) -> bytes:
    service_record_handle = (1).to_bytes(4, byteorder="big")
    max_attribute_byte_count = (0xFFFF).to_bytes(2, byteorder="big")
    attribute_id_list = build_attribute_id_list([ATTR_RANGE_ALL])
    continuation_state = b"\x00"
    params = (
        service_record_handle
        + max_attribute_byte_count
        + attribute_id_list
        + continuation_state
    )
    return b"\x04" + transaction_id.to_bytes(2, byteorder="big") + len(params).to_bytes(
        2, byteorder="big"
    ) + params


def get_templates() -> list[bytes]:
    """Return base valid request templates for mutation fuzzing modes."""
    return [
        _build_service_search_request(),
        _build_service_attribute_request(),
        build_service_search_attribute_request(),
    ]
