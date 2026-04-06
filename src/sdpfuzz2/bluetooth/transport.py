"""Transport protocol for SDP I/O."""

from typing import Protocol


class Transport(Protocol):
    """Contract for request/response transport."""

    def send(self, payload: bytes) -> None:
        """Send a request payload."""
        ...

    def receive(self, timeout_ms: int) -> bytes:
        """Receive a response payload."""
        ...
