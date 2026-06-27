"""Integration tests for SDPProbe with mock SDP server.

These tests exercise the complete SDP probe flow against a mock server
that simulates realistic SDP service discovery responses.
"""

import pytest

from sdpfuzz2.bluetooth.probe import ProbeResult, SDPProbe
from sdpfuzz2.domain.errors import TransportError


class MockSDPServer:
    """Simulates a Bluetooth device with SDP services."""

    def __init__(self, services_data: list[dict[str, bytes]]) -> None:
        """Initialize mock server with service response data.

        Args:
            services_data: List of dicts with 'attribute_bytes' and 'continuation_state'
        """
        self.services_data = services_data
        self.request_count = 0
        self.received_requests: list[bytes] = []

    def send(self, payload: bytes) -> None:
        """Record outgoing request."""
        self.received_requests.append(payload)
        self.request_count += 1

    def receive(self, timeout_ms: int) -> bytes:
        """Send back response for current request number."""
        if self.request_count > len(self.services_data):
            raise TransportError("No more service data available")

        service = self.services_data[self.request_count - 1]
        attribute_bytes = service["attribute_bytes"]
        continuation = service.get("continuation_state", b"")

        # Build SDP response packet matching parser expectations
        params = (
            len(attribute_bytes).to_bytes(2, byteorder="big")
            + attribute_bytes
            + len(continuation).to_bytes(1, byteorder="big")
            + continuation
        )

        response: bytes = (
            b"\x07"  # PDU type: Service Search Attribute Response
            + self.request_count.to_bytes(2, byteorder="big")  # transaction ID
            + len(params).to_bytes(2, byteorder="big")  # parameter length
            + params
        )
        return response


def test_probe_discovers_single_service_no_continuation() -> None:
    """Integration: probe should collect single service response with no continuation."""
    server = MockSDPServer(
        [
            {
                "attribute_bytes": b"\x35\x03\x09\x00\x01",  # minimal service record
                "continuation_state": b"",
            }
        ]
    )
    probe = SDPProbe(server, response_timeout_ms=1500)

    result = probe.collect_initial_state()

    assert isinstance(result, ProbeResult)
    assert len(result.attribute_list_fragments) == 1
    assert result.full_attribute_list == b"\x35\x03\x09\x00\x01"
    assert len(result.continuation_states) == 0
    assert server.request_count == 1


def test_probe_discovers_multiple_service_pages() -> None:
    """Integration: probe should paginate through services with continuation states."""
    server = MockSDPServer(
        [
            {
                "attribute_bytes": b"\x35\x05Service1",
                "continuation_state": b"\x01\x00",
            },
            {
                "attribute_bytes": b"\x35\x05Service2",
                "continuation_state": b"\x02\x00",
            },
            {
                "attribute_bytes": b"\x35\x05Service3",
                "continuation_state": b"",
            },
        ]
    )
    probe = SDPProbe(server)

    result = probe.collect_initial_state()

    assert len(result.attribute_list_fragments) == 3
    assert b"Service1" in result.full_attribute_list
    assert b"Service2" in result.full_attribute_list
    assert b"Service3" in result.full_attribute_list
    assert len(result.continuation_states) == 2
    assert server.request_count == 3


def test_probe_handles_realistic_service_discovery() -> None:
    """Integration: probe should handle typical SDP response sequence."""
    # Simulate a device with Bluetooth services: A2DP, HFP
    server = MockSDPServer(
        [
            {
                "attribute_bytes": (
                    b"\x35\x0c"  # sequence of 12 bytes
                    b"\x09\x00\x00"  # attribute ID
                    b"\x35\x05"  # service list (5 bytes)
                    b"\x19\x11\x0d"  # A2DP UUID
                ),
                "continuation_state": b"\x01",
            },
            {
                "attribute_bytes": (
                    b"\x35\x0c"
                    b"\x09\x00\x01"  # next attribute
                    b"\x35\x05"
                    b"\x19\x11\x1f"  # HFP UUID
                ),
                "continuation_state": b"",
            },
        ]
    )
    probe = SDPProbe(server)

    result = probe.collect_initial_state()

    assert len(result.attribute_list_fragments) == 2
    assert b"\x19\x11\x0d" in result.full_attribute_list  # A2DP
    assert b"\x19\x11\x1f" in result.full_attribute_list  # HFP
    assert len(result.continuation_states) == 1
    assert server.request_count == 2


def test_probe_records_continuation_states_in_order() -> None:
    """Integration: continuation states should be stored in discovery order."""
    server = MockSDPServer(
        [
            {"attribute_bytes": b"A1", "continuation_state": b"CS1"},
            {"attribute_bytes": b"A2", "continuation_state": b"CS2"},
            {"attribute_bytes": b"A3", "continuation_state": b"CS3"},
            {"attribute_bytes": b"A4", "continuation_state": b""},
        ]
    )
    probe = SDPProbe(server)

    result = probe.collect_initial_state()

    assert result.continuation_states == [b"CS1", b"CS2", b"CS3"]


def test_probe_timeout_propagates_from_server() -> None:
    """Integration: probe should handle transport timeout from mock server."""

    class FailingMockServer:
        def send(self, payload: bytes) -> None:
            pass

        def receive(self, timeout_ms: int) -> bytes:
            raise TransportError("Connection timed out")

    server = FailingMockServer()
    probe = SDPProbe(server)

    with pytest.raises(TransportError, match="Connection timed out"):
        probe.collect_initial_state()


def test_probe_collects_large_service_database() -> None:
    """Integration: probe should handle discovery of many services (stress test)."""
    # Simulate a device with many services across multiple pages
    services_data = []
    for page in range(10):
        is_last = page == 9
        continuation = b"" if is_last else bytes([page + 1])
        services_data.append(
            {
                "attribute_bytes": f"Page{page:02d}_services".encode(),
                "continuation_state": continuation,
            }
        )

    server = MockSDPServer(services_data)
    probe = SDPProbe(server)

    result = probe.collect_initial_state()

    assert server.request_count == 10
    assert len(result.attribute_list_fragments) == 10
    assert len(result.continuation_states) == 9
    for page in range(10):
        assert f"Page{page:02d}".encode() in result.full_attribute_list


def test_probe_respects_configured_timeout() -> None:
    """Integration: probe should pass configured timeout to transport."""

    class TimeoutTrackingServer:
        def __init__(self) -> None:
            self.timeouts_received: list[int] = []

        def send(self, payload: bytes) -> None:
            pass

        def receive(self, timeout_ms: int) -> bytes:
            self.timeouts_received.append(timeout_ms)
            params = b"\x00\x00\x00"  # empty response
            return b"\x07\x00\x01" + len(params).to_bytes(2, byteorder="big") + params

    server = TimeoutTrackingServer()
    probe = SDPProbe(server, response_timeout_ms=2500)

    probe.collect_initial_state()

    assert server.timeouts_received[0] == 2500
