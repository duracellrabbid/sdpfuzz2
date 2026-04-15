import random
import socket

import pytest
import typer
from typer.testing import CliRunner

from sdpfuzz2.bluetooth.discovery import (
    BlueZDiscoveryBackend,
    DiscoveryService,
    NoopDiscoveryBackend,
    RawDiscoveredDevice,
    _coerce_optional_str,
    _to_plain_object_map,
)
from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.bluetooth.probe import ProbeResult
from sdpfuzz2.cli import _probe_selected_target, _render_probe_debug, app, select_target_device
from sdpfuzz2.domain.errors import PacketParseError, TransportError
from sdpfuzz2.domain.models import Device, PacketLogEntry, RunLog
from sdpfuzz2.fuzzing.cont_state_byte_mutation import ContinuationStateByteMutationStrategy
from sdpfuzz2.fuzzing.cont_state_len_mutation import ContinuationStateLengthMutationStrategy
from sdpfuzz2.fuzzing.mutators import flip_bytes
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.sdp.continuation import mutate_continuation_state
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request
from sdpfuzz2.sdp.parser import parse_response


class _WrappedValue:
    def __init__(self, value: object) -> None:
        self.value = value


class _SocketStub:
    def __init__(
        self,
        *,
        recv_result: bytes = b"\x07\x00",
        send_error: OSError | None = None,
        recv_error: OSError | None = None,
    ) -> None:
        self.recv_result = recv_result
        self.send_error = send_error
        self.recv_error = recv_error
        self.connected_to: tuple[str, int] | None = None
        self.timeout: float | None = None
        self.closed = False

    def connect(self, addr: tuple[str, int]) -> None:
        self.connected_to = addr

    def send(self, payload: bytes) -> int:
        if self.send_error is not None:
            raise self.send_error
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


def test_random_bytes_strategy_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="min_length must be >= 1"):
        TotallyRandomBytesStrategy(min_length=0)

    with pytest.raises(ValueError, match="max_length must be >= min_length"):
        TotallyRandomBytesStrategy(min_length=4, max_length=3)

    with pytest.raises(ValueError, match="seed and rng are mutually exclusive"):
        TotallyRandomBytesStrategy(seed=1, rng=random.Random(1))


def test_continuation_length_strategy_validation_and_rollover() -> None:
    with pytest.raises(ValueError, match="transaction_id_start must be between 1 and 65535"):
        ContinuationStateLengthMutationStrategy(transaction_id_start=0)

    with pytest.raises(ValueError, match="min_oversized_length must be between 0 and 255"):
        ContinuationStateLengthMutationStrategy(min_oversized_length=256)

    with pytest.raises(ValueError, match="max_oversized_length must be between 0 and 255"):
        ContinuationStateLengthMutationStrategy(max_oversized_length=256)

    with pytest.raises(ValueError, match="max_oversized_length must be >= min_oversized_length"):
        ContinuationStateLengthMutationStrategy(min_oversized_length=10, max_oversized_length=9)

    with pytest.raises(ValueError, match="seed and rng are mutually exclusive"):
        ContinuationStateLengthMutationStrategy(seed=1, rng=random.Random(2))

    strategy = ContinuationStateLengthMutationStrategy(transaction_id_start=0xFFFF, seed=7)

    first_packet = strategy.next_packet()
    second_packet = strategy.next_packet()

    assert int.from_bytes(first_packet[1:3], byteorder="big") == 0xFFFF
    assert int.from_bytes(second_packet[1:3], byteorder="big") == 1


def test_continuation_byte_strategy_validation_and_rollover() -> None:
    with pytest.raises(ValueError, match="valid_continuation_states must not be empty"):
        ContinuationStateByteMutationStrategy(valid_continuation_states=[])

    with pytest.raises(ValueError, match="valid_continuation_states must contain non-empty states"):
        ContinuationStateByteMutationStrategy(valid_continuation_states=[b""])

    with pytest.raises(ValueError, match="transaction_id_start must be between 1 and 65535"):
        ContinuationStateByteMutationStrategy(
            valid_continuation_states=[b"\x01"],
            transaction_id_start=0,
        )

    with pytest.raises(ValueError, match="seed and rng are mutually exclusive"):
        ContinuationStateByteMutationStrategy(
            valid_continuation_states=[b"\x01"],
            seed=1,
            rng=random.Random(3),
        )

    strategy = ContinuationStateByteMutationStrategy(
        valid_continuation_states=[b"\x01\x02"],
        transaction_id_start=0xFFFF,
        seed=5,
    )

    first_packet = strategy.next_packet()
    second_packet = strategy.next_packet()

    assert int.from_bytes(first_packet[1:3], byteorder="big") == 0xFFFF
    assert int.from_bytes(second_packet[1:3], byteorder="big") == 1


def test_random_mutation_strategy_validation() -> None:
    with pytest.raises(ValueError, match="templates must not be empty"):
        RandomMutationStrategy(templates=[])

    with pytest.raises(ValueError, match="templates must contain non-empty packets"):
        RandomMutationStrategy(templates=[b""])

    with pytest.raises(ValueError, match="seed and rng are mutually exclusive"):
        RandomMutationStrategy(seed=1, rng=random.Random(4))


def test_flip_bytes_validation_and_empty_input() -> None:
    rng = random.Random(1)

    assert flip_bytes(b"", rng=rng) == b""

    with pytest.raises(ValueError, match="min_flips must be >= 1"):
        flip_bytes(b"abc", rng=rng, min_flips=0)

    with pytest.raises(ValueError, match="max_flips must be >= min_flips"):
        flip_bytes(b"abc", rng=rng, min_flips=3, max_flips=2)


def test_mutate_continuation_state_allows_empty_seed() -> None:
    assert mutate_continuation_state(b"", rng=random.Random(1)) == b""


def test_packet_builder_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="transaction_id must be between 0 and 65535"):
        build_service_search_attribute_request(transaction_id=-1)

    with pytest.raises(ValueError, match="continuation_state must be at most 255 bytes"):
        build_service_search_attribute_request(continuation_state=b"\x00" * 256)

    with pytest.raises(ValueError, match="max_attribute_byte_count must be between 0 and 65535"):
        build_service_search_attribute_request(max_attribute_byte_count=0x10000)


def test_packet_log_entry_and_run_log_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="crash must be 0 or 1"):
        PacketLogEntry(request_packet_hex="aa", response_packet_hex="bb", crash=2)

    with pytest.raises(ValueError, match="Invalid MAC address"):
        RunLog(
            device_name="Device",
            device_mac_address="INVALID",
            start_time="2026-04-06 12:00:00 UTC",
            logs=[],
        )


def test_select_target_device_rejects_empty_device_list() -> None:
    with pytest.raises(typer.BadParameter, match="No devices available for selection"):
        select_target_device([])


def test_scaffold_status_command_reports_phase_status() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scaffold-status"])

    assert result.exit_code == 0
    assert "Phase 0 scaffolding complete" in result.stdout
    assert "Phase 1 discovery complete" in result.stdout
    assert "Phase 2 SDP probing complete" in result.stdout


def test_l2cap_transport_default_socket_unavailable_raises_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "BTPROTO_L2CAP", None, raising=False)

    transport = L2CAPTransport(target_mac="00:11:22:33:44:55")

    with pytest.raises(TransportError, match="Bluetooth L2CAP sockets are not available"):
        transport.send(b"\x06\x00")


def test_l2cap_transport_builds_default_socket_when_platform_support_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_socket = _SocketStub()

    monkeypatch.setattr(socket, "BTPROTO_L2CAP", 99, raising=False)
    monkeypatch.setattr(socket, "AF_BLUETOOTH", 31, raising=False)
    monkeypatch.setattr(socket, "SOCK_SEQPACKET", 5, raising=False)
    monkeypatch.setattr(socket, "socket", lambda family, sock_type, proto: fake_socket)

    transport = L2CAPTransport(target_mac="00:11:22:33:44:55")

    transport.send(b"\x06\x00")

    assert fake_socket.connected_to == ("00:11:22:33:44:55", 0x0001)


def test_l2cap_transport_send_and_receive_oserror_paths() -> None:
    send_transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: _SocketStub(send_error=OSError("send failed")),
    )
    with pytest.raises(TransportError, match="Failed to send L2CAP payload"):
        send_transport.send(b"\x06\x00")

    recv_transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: _SocketStub(recv_error=OSError("recv failed")),
    )
    recv_transport.send(b"\x06\x00")
    with pytest.raises(TransportError, match="Failed to receive L2CAP payload"):
        recv_transport.receive(timeout_ms=100)


def test_l2cap_transport_rejects_empty_receive_and_closes_socket() -> None:
    fake_socket = _SocketStub(recv_result=b"")
    transport = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: fake_socket,
    )

    transport.send(b"\x06\x00")
    with pytest.raises(TransportError, match="Received empty payload from L2CAP socket"):
        transport.receive(timeout_ms=100)

    transport.close()
    assert fake_socket.closed is True


def test_discovery_service_covers_noop_and_helper_edges() -> None:
    assert NoopDiscoveryBackend().scan() == []
    assert _coerce_optional_str(123) is None

    plain_map = _to_plain_object_map(
        {
            "/org/bluez/hci0/dev_test": {
                "org.bluez.Device1": {
                    "Address": _WrappedValue("AA:BB:CC:DD:EE:FF"),
                    42: "ignored",
                },
                7: {},
            },
            99: {},
        }
    )

    assert plain_map == {
        "/org/bluez/hci0/dev_test": {
            "org.bluez.Device1": {"Address": "AA:BB:CC:DD:EE:FF"}
        }
    }


def test_bluez_backend_skips_objects_without_device_interface() -> None:
    managed_objects: dict[str, dict[str, dict[str, object]]] = {
        "/org/bluez/hci0": {"org.bluez.Adapter1": {"Powered": True}},
        "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF": {
            "org.bluez.Device1": {"Address": "AA:BB:CC:DD:EE:FF", "Alias": "Speaker"}
        },
    }

    backend = BlueZDiscoveryBackend(client=_BlueZClientStub(managed_objects))

    assert backend.scan() == [
        RawDiscoveredDevice(name="Speaker", mac_address="AA:BB:CC:DD:EE:FF")
    ]


class _BlueZClientStub:
    def __init__(self, managed_objects: dict[str, dict[str, dict[str, object]]]) -> None:
        self._managed_objects = managed_objects

    def scan_managed_objects(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:
        del timeout_seconds
        return self._managed_objects


def test_parser_rejects_payload_with_too_short_params() -> None:
    with pytest.raises(
        PacketParseError,
        match="too short for attribute list and continuation state",
    ):
        parse_response(b"\x07\x00\x01\x00\x02\x00\x00")


def test_discovery_service_can_return_unnamed_device_from_raw_input() -> None:
    discovered = DiscoveryService(
        backend=_BlueZClientDiscoveryBackendAdapter(
            [RawDiscoveredDevice(name=None, mac_address="00:11:22:33:44:55")]
        )
    ).discover(include_unnamed=True)

    assert discovered == [Device(name="Unknown Device", mac_address="00:11:22:33:44:55")]


def test_probe_selected_target_constructs_transport_and_collects_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    expected_result = ProbeResult(attribute_list_fragments=[b"\x35\x03"], continuation_states=[])

    class FakeTransport:
        def __init__(self, *, target_mac: str) -> None:
            captured["target_mac"] = target_mac

    class FakeProbe:
        def __init__(self, *, transport: object, response_timeout_ms: int) -> None:
            captured["transport"] = transport
            captured["response_timeout_ms"] = response_timeout_ms

        def collect_initial_state(self) -> ProbeResult:
            return expected_result

    monkeypatch.setattr("sdpfuzz2.cli.L2CAPTransport", FakeTransport)
    monkeypatch.setattr("sdpfuzz2.cli.SDPProbe", FakeProbe)

    target = Device(name="Alpha", mac_address="00:11:22:33:44:55")
    result = _probe_selected_target(target, response_timeout_ms=900)

    assert captured["target_mac"] == "00:11:22:33:44:55"
    assert captured["response_timeout_ms"] == 900
    assert result is expected_result


def test_render_probe_debug_includes_none_when_no_continuation_states(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _render_probe_debug(ProbeResult(attribute_list_fragments=[b"\x35\x03"], continuation_states=[]))

    captured = capsys.readouterr()
    assert "Debug probe details:" in captured.out
    assert "attribute_page[1]_hex=3503" in captured.out
    assert "continuation_state: none" in captured.out


class _BlueZClientDiscoveryBackendAdapter:
    def __init__(self, devices: list[RawDiscoveredDevice]) -> None:
        self._devices = devices

    def scan(self) -> list[RawDiscoveredDevice]:
        return self._devices