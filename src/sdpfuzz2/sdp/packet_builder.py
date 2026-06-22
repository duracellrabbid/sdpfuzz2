"""SDP packet builder helpers."""

PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST = 0x06

# SDP Data Element type descriptors (top 5 bits = type, bottom 3 bits = size descriptor)
_DE_TYPE_UINT = 0x08       # Unsigned integer
_DE_TYPE_UUID = 0x18       # UUID
_DE_TYPE_SEQUENCE = 0x30   # Data element sequence

# Size descriptors for inline sizes
_DE_SIZE_2_BYTES = 0x01    # 2-byte value (combined with type: e.g. 0x19 = UUID 2-byte)
_DE_SIZE_4_BYTES = 0x02    # 4-byte value
_DE_SIZE_LEN1 = 0x05       # Length in following 1 byte


def encode_uuid(uuid: int) -> bytes:
    """Encode a 16-bit or 32-bit UUID as an SDP data element.

    UUIDs in range 0x0000–0xFFFF are encoded as 2-byte UUIDs (type 0x19).
    UUIDs in range 0x00010000–0xFFFFFFFF are encoded as 4-byte UUIDs (type 0x1A).
    """
    if 0 <= uuid <= 0xFFFF:
        return bytes((_DE_TYPE_UUID | _DE_SIZE_2_BYTES,)) + uuid.to_bytes(2, byteorder="big")
    if uuid <= 0xFFFFFFFF:
        return bytes((_DE_TYPE_UUID | _DE_SIZE_4_BYTES,)) + uuid.to_bytes(4, byteorder="big")
    raise ValueError(f"UUID value 0x{uuid:X} exceeds 32 bits; use a 128-bit UUID bytes literal")


def encode_attribute_id(attribute_id: int) -> bytes:
    """Encode a single 16-bit attribute ID as an SDP uint16 data element (type 0x09)."""
    if not 0 <= attribute_id <= 0xFFFF:
        raise ValueError("attribute_id must be a 16-bit value (0x0000–0xFFFF)")
    return bytes((_DE_TYPE_UINT | _DE_SIZE_2_BYTES,)) + attribute_id.to_bytes(2, byteorder="big")


def encode_attribute_range(start: int, end: int) -> bytes:
    """Encode an attribute ID range [start, end] as an SDP uint32 data element (type 0x0A).

    The high 16 bits carry *start* and the low 16 bits carry *end*, as per the SDP spec.
    """
    if not (0 <= start <= 0xFFFF and 0 <= end <= 0xFFFF):
        raise ValueError("Attribute range start/end must be 16-bit values")
    if start > end:
        raise ValueError("Attribute range start must not exceed end")
    packed = (start << 16) | end
    return bytes((_DE_TYPE_UINT | _DE_SIZE_4_BYTES,)) + packed.to_bytes(4, byteorder="big")


def build_de_sequence(elements: list[bytes]) -> bytes:
    """Wrap a list of encoded data elements in an SDP Data Element Sequence.

    Sequences up to 255 bytes in length use a 1-byte length field (type 0x35).
    Larger sequences use a 2-byte length field (type 0x36).
    """
    body = b"".join(elements)
    if len(body) <= 0xFF:
        return bytes((_DE_TYPE_SEQUENCE | _DE_SIZE_LEN1, len(body))) + body
    if len(body) <= 0xFFFF:
        return bytes((_DE_TYPE_SEQUENCE | 0x06,)) + len(body).to_bytes(2, byteorder="big") + body
    raise ValueError("Data element sequence body exceeds 65535 bytes")


def build_service_search_pattern(uuids: list[int]) -> bytes:
    """Build the ServiceSearchPattern data element sequence from a list of UUIDs."""
    if not uuids:
        raise ValueError("At least one UUID is required in the service search pattern")
    return build_de_sequence([encode_uuid(u) for u in uuids])


def build_attribute_id_list(
    attributes: list[int | tuple[int, int]],
) -> bytes:
    """Build the AttributeIDList data element sequence.

    Each element may be either:
    - An ``int`` for a single attribute ID (encoded as uint16), or
    - A ``(start, end)`` tuple for an inclusive attribute range (encoded as uint32).
    """
    if not attributes:
        raise ValueError("At least one attribute ID or range is required")
    elements: list[bytes] = []
    for attr in attributes:
        if isinstance(attr, tuple):
            elements.append(encode_attribute_range(attr[0], attr[1]))
        else:
            elements.append(encode_attribute_id(attr))
    return build_de_sequence(elements)


# Default request parameters (Public Browse Group root; all attributes)
UUID_PUBLIC_BROWSE_GROUP = 0x1002
ATTR_RANGE_ALL = (0x0000, 0xFFFF)


def build_service_search_attribute_request(
    *,
    transaction_id: int = 1,
    continuation_state: bytes = b"",
    max_attribute_byte_count: int = 0xFFFF,
    uuids: list[int] | None = None,
    attributes: list[int | tuple[int, int]] | None = None,
) -> bytes:
    """Build a valid Service Search Attribute request packet.

    The default request asks for all attributes from records matching the
    Public Browse Group root and starts with an empty continuation state.

    Args:
        transaction_id: SDP transaction ID (0–65535).
        continuation_state: Opaque continuation state from a prior response.
        max_attribute_byte_count: Maximum bytes the peer may return (0–65535).
        uuids: UUIDs for the ServiceSearchPattern. Defaults to [UUID_PUBLIC_BROWSE_GROUP].
        attributes: Attribute IDs or (start, end) ranges for the AttributeIDList.
            Defaults to [(0x0000, 0xFFFF)] (all attributes).
    """
    if not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("transaction_id must be between 0 and 65535")
    if len(continuation_state) > 0xFF:
        raise ValueError("continuation_state must be at most 255 bytes")
    if not 0 <= max_attribute_byte_count <= 0xFFFF:
        raise ValueError("max_attribute_byte_count must be between 0 and 65535")

    search_pattern = build_service_search_pattern(uuids if uuids is not None else [UUID_PUBLIC_BROWSE_GROUP])
    attribute_id_list = build_attribute_id_list(attributes if attributes is not None else [ATTR_RANGE_ALL])

    params = (
        search_pattern
        + max_attribute_byte_count.to_bytes(2, byteorder="big")
        + attribute_id_list
        + bytes((len(continuation_state),))
        + continuation_state
    )
    header = (
        bytes((PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST,))
        + transaction_id.to_bytes(2, byteorder="big")
        + len(params).to_bytes(2, byteorder="big")
    )
    return header + params
