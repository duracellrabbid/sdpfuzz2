import pytest

from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.domain.errors import TransportError


class FakeSocket:
    def __init__(
        self,
        *,
        send_result: int = 0,
        recv_result: bytes = b"\x01",
        connect_error: OSError | None = None,
        send_error: OSError | None = None,
        recv_error: OSError | None = None,
    ) -> None:
        self.send_result = send_result
        self.recv_result = recv_result
        self.connect_error = connect_error
        self.send_error = send_error
        self.recv_error = recv_error
        self.connected_to: tuple[str, int] | None = None
        self.timeout: float | None = None
        self.closed = False

    def connect(self, addr: tuple[str, int]) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        self.connected_to = addr

    def send(self, payload: bytes) -> int:
        if self.send_error is not None:
            raise self.send_error
        if self.send_result:
            return self.send_result
        return len(payload)

    def recv(self, recv_size: int) -> bytes:
        del recv_size
        if self.recv_error is not None:
            raise self.recv_error
        return self.recv_result

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def close(self) -> None:
        self.closed = True


def test_l2cap_transport_send_receive_happy_path() -> None:
    fake_socket = FakeSocket(recv_result=b"\x07\x00")

    transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: fake_socket,
    )

    transport.send(b"\x06\x00")
    response = transport.receive(timeout_ms=1500)

    assert fake_socket.connected_to == ("00:11:22:33:44:55", 0x0001)
    assert fake_socket.timeout == pytest.approx(1.5)
    assert response == b"\x07\x00"


def test_l2cap_transport_connect_failure_raises_transport_error() -> None:
    fake_socket = FakeSocket(connect_error=OSError("connect failed"))
    transport = L2CAPTransport(
        target_mac="AA:BB:CC:DD:EE:FF",
        socket_factory=lambda: fake_socket,
    )

    with pytest.raises(TransportError, match="Failed to connect L2CAP socket"):
        transport.send(b"\x06\x00")

    assert fake_socket.closed is True


def test_l2cap_transport_partial_send_raises_transport_error() -> None:
    transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: FakeSocket(send_result=1),
    )

    with pytest.raises(TransportError, match="Partial L2CAP send"):
        transport.send(b"\x06\x00")


def test_l2cap_transport_receive_timeout_raises_transport_error() -> None:
    timeout_exc = TimeoutError("timed out")
    transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: FakeSocket(recv_error=timeout_exc),
    )

    transport.send(b"\x06\x00")
    with pytest.raises(TransportError, match="Timed out waiting for L2CAP response"):
        transport.receive(timeout_ms=500)


def test_l2cap_transport_input_validation() -> None:
    transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: FakeSocket(),
    )

    with pytest.raises(ValueError, match="payload must not be empty"):
        transport.send(b"")

    with pytest.raises(ValueError, match="timeout_ms must be greater than 0"):
        transport.receive(timeout_ms=0)
