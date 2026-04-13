"""Linux L2CAP transport for SDP request/response I/O."""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Protocol

from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.domain.errors import TransportError


class _SocketLike(Protocol):
    def connect(self, addr: tuple[str, int]) -> None: ...

    def send(self, payload: bytes) -> int: ...

    def recv(self, recv_size: int) -> bytes: ...

    def settimeout(self, timeout: float) -> None: ...

    def close(self) -> None: ...


class L2CAPTransport(Transport):
    """Concrete L2CAP transport used by the probe flow on Linux/BlueZ."""

    def __init__(
        self,
        *,
        target_mac: str,
        psm: int = 0x0001,
        recv_size: int = 4096,
        socket_factory: Callable[[], _SocketLike] | None = None,
    ) -> None:
        self._target_mac = target_mac
        self._psm = psm
        self._recv_size = recv_size
        self._socket_factory = socket_factory or self._build_default_socket
        self._socket: _SocketLike | None = None

    def _build_default_socket(self) -> _SocketLike:
        if not all(
            hasattr(socket, attr) for attr in ("AF_BLUETOOTH", "SOCK_SEQPACKET", "BTPROTO_L2CAP")
        ):
            raise TransportError(
                "Bluetooth L2CAP sockets are not available on this platform/Python build"
            )

        return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)

    def _ensure_connected(self) -> _SocketLike:
        if self._socket is not None:
            return self._socket

        sock = self._socket_factory()
        try:
            sock.connect((self._target_mac, self._psm))
        except OSError as exc:
            sock.close()
            raise TransportError(
                f"Failed to connect L2CAP socket to {self._target_mac}: {exc}"
            ) from exc

        self._socket = sock
        return sock

    def send(self, payload: bytes) -> None:
        if not payload:
            raise ValueError("payload must not be empty")

        sock = self._ensure_connected()
        try:
            sent = sock.send(payload)
        except OSError as exc:
            raise TransportError(f"Failed to send L2CAP payload: {exc}") from exc

        if sent != len(payload):
            raise TransportError(
                f"Partial L2CAP send detected: sent {sent} of {len(payload)} bytes"
            )

    def receive(self, timeout_ms: int) -> bytes:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be greater than 0")

        sock = self._ensure_connected()
        sock.settimeout(timeout_ms / 1000)
        try:
            data = sock.recv(self._recv_size)
        except TimeoutError as exc:
            raise TransportError(f"Timed out waiting for L2CAP response ({timeout_ms} ms)") from exc
        except OSError as exc:
            raise TransportError(f"Failed to receive L2CAP payload: {exc}") from exc

        if not data:
            raise TransportError("Received empty payload from L2CAP socket")

        return data

    def close(self) -> None:
        """Close the underlying socket if one has been established."""
        if self._socket is not None:
            self._socket.close()
            self._socket = None
