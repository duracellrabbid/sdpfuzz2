import pytest

from sdpfuzz2.bluetooth.crash_detector import CrashDetector
from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.bluetooth.probe import SDPProbe
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.domain.enums import FuzzMode
from sdpfuzz2.domain.errors import PacketParseError, SDPFuzzError, TransportError
from sdpfuzz2.fuzzing.cont_state_byte_mutation import ContinuationStateByteMutationStrategy
from sdpfuzz2.fuzzing.cont_state_len_mutation import ContinuationStateLengthMutationStrategy
from sdpfuzz2.fuzzing.mutators import flip_bytes
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.logging.schema import PacketLogEntry, RunLog
from sdpfuzz2.orchestration.runner import FuzzRunner
from sdpfuzz2.orchestration.scheduler import WorkerScheduler
from sdpfuzz2.orchestration.session import FuzzSession
from sdpfuzz2.orchestration.workers import FuzzWorker
from sdpfuzz2.sdp.continuation import mutate_continuation_state
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request
from sdpfuzz2.sdp.parser import parse_response
from sdpfuzz2.sdp.templates import get_templates


class _NoopTransport:
    def send(self, payload: bytes) -> None:
        del payload

    def receive(self, timeout_ms: int) -> bytes:
        del timeout_ms
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"


class _SocketStub:
    def __init__(self) -> None:
        self.connected_to: tuple[str, int] | None = None
        self.timeout: float | None = None

    def connect(self, addr: tuple[str, int]) -> None:
        self.connected_to = addr

    def send(self, payload: bytes) -> int:
        return len(payload)

    def recv(self, recv_size: int) -> bytes:
        del recv_size
        return b"\x07\x00\x01\x00\x03\x00\x00\x00"

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def close(self) -> None:
        return None


def test_placeholder_components_behave_as_scaffolded() -> None:
    assert CrashDetector().should_stop() is False

    result = SDPProbe(transport=_NoopTransport()).collect_initial_state()
    assert result.attribute_list_fragments == [b""]
    assert result.continuation_states == []

    socket_stub = _SocketStub()
    l2cap = L2CAPTransport(
        target_mac="00:11:22:33:44:55",
        socket_factory=lambda: socket_stub,
    )
    l2cap.send(b"payload")
    assert l2cap.receive(timeout_ms=100).startswith(b"\x07")

    random_packet = TotallyRandomBytesStrategy(seed=1).next_packet()
    assert isinstance(random_packet, bytes)
    assert 16 <= len(random_packet) <= 64
    oversized_packet = ContinuationStateLengthMutationStrategy(seed=2).next_packet()
    assert oversized_packet[0] == 0x06

    cont_state_packet = ContinuationStateByteMutationStrategy(
        valid_continuation_states=[b"\x01\x02\x03"],
        seed=3,
    ).next_packet()
    assert cont_state_packet[0] == 0x06

    random_mutation_packet = RandomMutationStrategy(seed=4).next_packet()
    assert isinstance(random_mutation_packet, bytes)

    import random

    assert flip_bytes(b"abc", rng=random.Random(1)) != b"abc"
    assert mutate_continuation_state(b"\x01\x02", rng=random.Random(2)) != b"\x01\x02"
    assert len(get_templates()) == 3

    assert build_service_search_attribute_request().startswith(b"\x06")
    assert parse_response(b"\x07\x00\x01\x00\x03\x00\x00\x00")["has_more"] is False

    with pytest.raises(NotImplementedError):
        FuzzRunner().run()
    with pytest.raises(NotImplementedError):
        WorkerScheduler().start()
    with pytest.raises(NotImplementedError):
        FuzzWorker().run()


def test_session_and_config_defaults() -> None:
    session = FuzzSession(target_mac="AA:BB:CC:DD:EE:FF", mode="totally_random_bytes")
    config = RuntimeConfig()

    assert session.target_mac == "AA:BB:CC:DD:EE:FF"
    assert session.mode == "totally_random_bytes"
    assert config.concurrency == 1
    assert config.queue_size == 64
    assert config.response_timeout_ms == 1500


def test_domain_enums_and_errors() -> None:
    assert FuzzMode.TOTALLY_RANDOM_BYTES.value == "totally_random_bytes"
    assert issubclass(TransportError, SDPFuzzError)
    assert issubclass(PacketParseError, SDPFuzzError)


def test_logging_schema_re_exports_models() -> None:
    entry = PacketLogEntry(request_packet_hex="01", response_packet_hex="02", crash=0)
    log = RunLog(
        device_name="Device",
        device_mac_address="00:11:22:33:44:55",
        start_time="2026-04-06 12:00:00 UTC",
        logs=[entry],
    )

    assert log.logs[0].request_packet_hex == "01"
