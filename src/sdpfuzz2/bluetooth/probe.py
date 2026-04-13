"""Initial valid SDP probing logic."""

from dataclasses import dataclass

from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request
from sdpfuzz2.sdp.parser import parse_response


@dataclass(frozen=True)
class ProbeResult:
    """Result of probing valid SDP state before fuzzing starts."""

    attribute_list_fragments: list[bytes]
    continuation_states: list[bytes]

    @property
    def full_attribute_list(self) -> bytes:
        """Return the concatenated attribute-list payload across all pages."""
        return b"".join(self.attribute_list_fragments)


class SDPProbe:
    """Collect valid services and continuation states before fuzzing."""

    def __init__(
        self,
        transport: Transport,
        *,
        response_timeout_ms: int = 1500,
        initial_transaction_id: int = 1,
    ) -> None:
        self._transport = transport
        self._response_timeout_ms = response_timeout_ms
        self._transaction_id = initial_transaction_id

    def collect_initial_state(self) -> ProbeResult:
        continuation_state = b""
        continuation_states: list[bytes] = []
        fragments: list[bytes] = []

        while True:
            request_payload = build_service_search_attribute_request(
                transaction_id=self._transaction_id,
                continuation_state=continuation_state,
            )
            self._transport.send(request_payload)

            response_payload = self._transport.receive(timeout_ms=self._response_timeout_ms)
            parsed = parse_response(response_payload)

            fragments.append(parsed["attribute_lists"])

            continuation_state = parsed["continuation_state"]
            if continuation_state:
                continuation_states.append(continuation_state)
                self._transaction_id = (self._transaction_id + 1) & 0xFFFF
                continue

            break

        return ProbeResult(
            attribute_list_fragments=fragments,
            continuation_states=continuation_states,
        )
