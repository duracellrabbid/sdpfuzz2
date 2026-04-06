"""Linux L2CAP transport placeholder."""

from sdpfuzz2.bluetooth.transport import Transport


class L2CAPTransport(Transport):
    """Concrete transport to be implemented for Kali runtime."""

    def send(self, payload: bytes) -> None:
        raise NotImplementedError("Implemented in Phase 2/4")

    def receive(self, timeout_ms: int) -> bytes:
        raise NotImplementedError("Implemented in Phase 2/4")
