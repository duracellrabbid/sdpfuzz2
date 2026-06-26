"""Unit tests for sdpfuzz2.sdp.packet_builder."""

import pytest

from sdpfuzz2.sdp.packet_builder import (
    encode_uuid,
    encode_attribute_id,
    encode_attribute_range,
    build_de_sequence,
    build_service_search_pattern,
    build_attribute_id_list,
    build_service_search_attribute_request,
)


def test_encode_uuid_valid_16_bit() -> None:
    # UUIDs in range 0x0000–0xFFFF should be encoded as 2-byte UUIDs (type 0x19)
    res = encode_uuid(0x1234)
    assert res == b"\x19\x12\x34"


def test_encode_uuid_valid_32_bit() -> None:
    # UUIDs in range 0x00010000–0xFFFFFFFF should be encoded as 4-byte UUIDs (type 0x1A)
    res = encode_uuid(0x12345678)
    assert res == b"\x1a\x12\x34\x56\x78"


def test_encode_uuid_invalid_exceeds_32_bit() -> None:
    with pytest.raises(ValueError, match="exceeds 32 bits"):
        encode_uuid(0x100000000)


def test_encode_uuid_invalid_negative() -> None:
    with pytest.raises((ValueError, OverflowError)):
        encode_uuid(-1)


def test_encode_attribute_id_valid() -> None:
    res = encode_attribute_id(0x1234)
    assert res == b"\x09\x12\x34"


def test_encode_attribute_id_invalid() -> None:
    with pytest.raises(ValueError, match="attribute_id must be a 16-bit value"):
        encode_attribute_id(-1)

    with pytest.raises(ValueError, match="attribute_id must be a 16-bit value"):
        encode_attribute_id(0x10000)


def test_encode_attribute_range_valid() -> None:
    res = encode_attribute_range(0x1000, 0x2000)
    assert res == b"\x0a\x10\x00\x20\x00"


def test_encode_attribute_range_invalid_values() -> None:
    with pytest.raises(ValueError, match="Attribute range start/end must be 16-bit values"):
        encode_attribute_range(-1, 0x1000)

    with pytest.raises(ValueError, match="Attribute range start/end must be 16-bit values"):
        encode_attribute_range(0x1000, 0x10000)


def test_encode_attribute_range_start_exceeds_end() -> None:
    with pytest.raises(ValueError, match="Attribute range start must not exceed end"):
        encode_attribute_range(0x2000, 0x1000)


def test_build_de_sequence_small() -> None:
    # Smaller than or equal to 255 bytes sequence
    elements = [b"\x09\x12\x34", b"\x09\x56\x78"]
    res = build_de_sequence(elements)
    assert res == b"\x35\x06\x09\x12\x34\x09\x56\x78"


def test_build_de_sequence_medium() -> None:
    # Between 256 and 65535 bytes sequence
    elements = [b"\x00" * 300]
    res = build_de_sequence(elements)
    assert res == b"\x36\x01\x2c" + (b"\x00" * 300)


def test_build_de_sequence_too_large() -> None:
    # Exceeds 65535 bytes
    elements = [b"\x00" * 65536]
    with pytest.raises(ValueError, match="Data element sequence body exceeds 65535 bytes"):
        build_de_sequence(elements)


def test_build_service_search_pattern_valid() -> None:
    res = build_service_search_pattern([0x1234])
    assert res == b"\x35\x03\x19\x12\x34"


def test_build_service_search_pattern_empty() -> None:
    with pytest.raises(ValueError, match="At least one UUID is required"):
        build_service_search_pattern([])


def test_build_attribute_id_list_valid() -> None:
    # Mix of attributes and ranges
    res = build_attribute_id_list([0x1234, (0x1000, 0x2000)])
    assert res == b"\x35\x08\x09\x12\x34\x0a\x10\x00\x20\x00"


def test_build_attribute_id_list_empty() -> None:
    with pytest.raises(ValueError, match="At least one attribute ID or range is required"):
        build_attribute_id_list([])


def test_build_service_search_attribute_request_custom() -> None:
    res = build_service_search_attribute_request(
        transaction_id=42,
        continuation_state=b"\x01\x02",
        max_attribute_byte_count=100,
        uuids=[0x1101],
        attributes=[0x0001],
    )
    # PDU ID: 0x06
    # Transaction ID: 0x002A (42)
    # Parameter Length: len(params)
    # search_pattern = b"\x35\x03\x19\x11\x01" (5 bytes)
    # max_attribute_byte_count = b"\x00\x64" (2 bytes)
    # attribute_id_list = b"\x35\x03\x09\x00\x01" (5 bytes)
    # continuation_state_length = 0x02 (1 byte)
    # continuation_state = b"\x01\x02" (2 bytes)
    # total param len = 5 + 2 + 5 + 1 + 2 = 15 = 0x000F
    assert res.startswith(b"\x06\x00\x2a\x00\x0f")
