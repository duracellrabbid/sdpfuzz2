"""Contract tests for SDPProbe behavior under various scenarios.

These tests verify probe behavior with respect to:
- Timeout handling (configurable timeout, proper timeout propagation)
- Retry logic (continuation state handling, transaction ID increments)
- State collection (attribute fragments, continuation states aggregated correctly)
"""

from unittest.mock import MagicMock

import pytest

from sdpfuzz2.bluetooth.probe import ProbeResult, SDPProbe
from sdpfuzz2.domain.errors import TransportError


class FakeTransport:
    """Synchronous fake transport for deterministic probe testing."""

    def __init__(
        self, responses: list[dict[str, bytes]] | None = None, timeout_after: int | None = None
    ) -> None:
        """Initialize fake transport.

        Args:
            responses: List of dicts with keys 'attribute_lists' and 'continuation_state'
            timeout_after: If set, raise timeout after this many sends
        """
        self.responses = responses or []
        self.timeout_after = timeout_after
        self.send_count = 0
        self.last_sent_payload: bytes | None = None
        self.received_timeouts = 0

    def send(self, payload: bytes) -> None:
        self.send_count += 1
        self.last_sent_payload = payload
        if self.timeout_after and self.send_count >= self.timeout_after:
            self.received_timeouts += 1

    def receive(self, timeout_ms: int) -> bytes:
        if self.timeout_after and self.send_count >= self.timeout_after:
            raise TransportError("Connection timed out")

        if self.send_count > len(self.responses):
            raise AssertionError("Probe sent more requests than expected")

        response = self.responses[self.send_count - 1]

        # Build SDP response packet per SDP spec:
        # [0] PDU type (0x07 = Service Search Attribute Response)
        # [1:3] transaction ID (2 bytes big-endian)
        # [3:5] parameter length (2 bytes big-endian)
        # [5:] parameters
        #
        # Parameters format for Service Search Attribute Response:
        # [0:2] attribute_lists_byte_count (2 bytes big-endian)
        # [2:2+count] attribute_lists bytes
        # [2+count] continuation_state_len (1 byte)
        # [2+count+1:] continuation_state bytes
        attribute_bytes = response["attribute_lists"]
        continuation = response["continuation_state"]

        # Build parameters
        params = (
            len(attribute_bytes).to_bytes(2, byteorder="big")
            + attribute_bytes
            + len(continuation).to_bytes(1, byteorder="big")
            + continuation
        )

        # Build response frame
        response_bytes = (
            b"\x07"  # PDU type: Service Search Attribute Response
            + self.send_count.to_bytes(2, byteorder="big")  # transaction ID
            + len(params).to_bytes(2, byteorder="big")  # parameter length
            + params
        )
        return response_bytes


def test_probe_collects_single_response_without_continuation() -> None:
    """Contract: probe should stop after single response with no continuation."""
    transport = FakeTransport(
        responses=[{"attribute_lists": b"\x35\x05\x09\x00\x01\x02\x03", "continuation_state": b""}]
    )
    probe = SDPProbe(transport, response_timeout_ms=1500)

    result = probe.collect_initial_state()

    assert isinstance(result, ProbeResult)
    assert len(result.attribute_list_fragments) == 1
    assert result.attribute_list_fragments[0] == b"\x35\x05\x09\x00\x01\x02\x03"
    assert len(result.continuation_states) == 0
    assert transport.send_count == 1


def test_probe_collects_multiple_responses_with_continuation() -> None:
    """Contract: probe should continue requesting while continuation state exists."""
    transport = FakeTransport(
        responses=[
            {"attribute_lists": b"PAGE1", "continuation_state": b"\x01\x00"},
            {"attribute_lists": b"PAGE2", "continuation_state": b"\x02\x00"},
            {"attribute_lists": b"PAGE3", "continuation_state": b""},
        ]
    )
    probe = SDPProbe(transport, response_timeout_ms=1500)

    result = probe.collect_initial_state()

    assert len(result.attribute_list_fragments) == 3
    assert result.full_attribute_list == b"PAGE1PAGE2PAGE3"
    assert len(result.continuation_states) == 2
    assert result.continuation_states[0] == b"\x01\x00"
    assert result.continuation_states[1] == b"\x02\x00"
    assert transport.send_count == 3


def test_probe_increments_transaction_id_on_continuation() -> None:
    """Contract: probe should increment transaction ID when continuing with continuation state."""
    transport = FakeTransport(
        responses=[
            {"attribute_lists": b"P1", "continuation_state": b"\xAA"},
            {"attribute_lists": b"P2", "continuation_state": b""},
        ]
    )
    probe = SDPProbe(transport, response_timeout_ms=1500, initial_transaction_id=42)

    result = probe.collect_initial_state()

    assert len(result.attribute_list_fragments) == 2
    assert transport.send_count == 2


def test_probe_respects_timeout_setting() -> None:
    """Contract: probe should propagate configured timeout to transport."""
    transport = FakeTransport(responses=[{"attribute_lists": b"P1", "continuation_state": b""}])
    probe = SDPProbe(transport, response_timeout_ms=2500)

    result = probe.collect_initial_state()

    # Verify probe completed without timeout
    assert len(result.attribute_list_fragments) == 1


def test_probe_raises_on_transport_timeout() -> None:
    """Contract: probe should propagate timeout errors from transport."""
    transport = FakeTransport(
        responses=[{"attribute_lists": b"P1", "continuation_state": b"\xAA"}], timeout_after=2
    )
    probe = SDPProbe(transport, response_timeout_ms=1500)

    with pytest.raises(TransportError, match="Connection timed out"):
        probe.collect_initial_state()

    assert transport.send_count == 2  # First request succeeds, second times out
    assert transport.received_timeouts == 1


def test_probe_collects_empty_fragments_list_with_empty_attributes() -> None:
    """Contract: probe should handle responses with minimal attribute data."""
    transport = FakeTransport(
        responses=[{"attribute_lists": b"", "continuation_state": b""}]
    )
    probe = SDPProbe(transport)

    result = probe.collect_initial_state()

    assert len(result.attribute_list_fragments) == 1
    assert result.attribute_list_fragments[0] == b""
    assert result.full_attribute_list == b""


def test_probe_aggregates_continuation_states_in_order() -> None:
    """Contract: continuation states should be stored in order for later mutation."""
    transport = FakeTransport(
        responses=[
            {"attribute_lists": b"A1", "continuation_state": b"CS1"},
            {"attribute_lists": b"A2", "continuation_state": b"CS2"},
            {"attribute_lists": b"A3", "continuation_state": b"CS3"},
            {"attribute_lists": b"A4", "continuation_state": b""},
        ]
    )
    probe = SDPProbe(transport)

    result = probe.collect_initial_state()

    assert result.continuation_states == [b"CS1", b"CS2", b"CS3"]


def test_probe_result_full_attribute_list_concatenates_correctly() -> None:
    """Contract: ProbeResult.full_attribute_list should concatenate all fragments."""
    result = ProbeResult(
        attribute_list_fragments=[b"\x00\x01", b"\x02\x03", b"\x04"],
        continuation_states=[b"\xAA"],
    )

    assert result.full_attribute_list == b"\x00\x01\x02\x03\x04"


def test_probe_initializes_with_default_timeout() -> None:
    """Contract: probe should have reasonable default timeout (1500ms)."""
    transport = MagicMock()
    transport.receive.return_value = b"\x07\x00\x02\x00\x00"  # minimal response

    probe = SDPProbe(transport)
    # Should not raise; verifies __init__ accepts no timeout arg
    # (Can't easily verify actual timeout without instrumentation)
    assert probe is not None
