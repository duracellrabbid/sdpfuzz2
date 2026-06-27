"""Integration tests for complete E2E workflows - tasks 10.1 to 10.6."""

import json
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sdpfuzz2.cli import app
from sdpfuzz2.domain.errors import TransportError
from sdpfuzz2.domain.models import Device
from sdpfuzz2.logging.schema import FuzzingSession


# 10.1: Build minimal mock SDP server for repeatable integration tests
class MockSDPServerState:
    """Shared state for the mock SDP server representing a Bluetooth target."""

    def __init__(
        self,
        services: list[bytes],
        continuation_states: list[bytes] = None,
        crash_after_packets: int = 999999,
    ) -> None:
        self.lock = threading.Lock()
        self.services = services
        self.continuation_states = continuation_states or []
        self.crash_after_packets = crash_after_packets

        self.probe_request_count = 0
        self.fuzz_request_count = 0
        self.is_crashed = False
        self.received_payloads: list[bytes] = []


class MockSDPServerTransport:
    """Thread-safe Transport mock wrapper that delegates to shared state."""

    def __init__(self, state: MockSDPServerState, *args, **kwargs) -> None:
        self.state = state

    def send(self, payload: bytes) -> None:
        with self.state.lock:
            if self.state.is_crashed:
                raise OSError("Connection refused")
            self.state.received_payloads.append(payload)

    def receive(self, timeout_ms: int) -> bytes:
        with self.state.lock:
            if self.state.is_crashed:
                raise TimeoutError("timed out")

            if not self.state.received_payloads:
                raise TransportError("No request received before receive call")

            last_payload = self.state.received_payloads[-1]
            tx_id = (
                int.from_bytes(last_payload[1:3], byteorder="big") if len(last_payload) >= 3 else 1
            )

            # Check for Service Search Attribute Request (0x06)
            if len(last_payload) > 0 and last_payload[0] == 0x06:
                if self.state.probe_request_count < len(self.state.services):
                    service_data = self.state.services[self.state.probe_request_count]
                    cont = (
                        self.state.continuation_states[self.state.probe_request_count]
                        if self.state.probe_request_count < len(self.state.continuation_states)
                        else b""
                    )
                    self.state.probe_request_count += 1

                    params = (
                        len(service_data).to_bytes(2, byteorder="big")
                        + service_data
                        + len(cont).to_bytes(1, byteorder="big")
                        + cont
                    )
                    return (
                        b"\x07"
                        + tx_id.to_bytes(2, byteorder="big")
                        + len(params).to_bytes(2, byteorder="big")
                        + params
                    )

            # Fuzz packet received
            self.state.fuzz_request_count += 1
            if self.state.fuzz_request_count >= self.state.crash_after_packets:
                self.state.is_crashed = True
                raise TimeoutError("timed out")

            pdu_type = last_payload[0] if len(last_payload) > 0 else 0x06
            resp_pdu = pdu_type + 1
            params = b"\x00\x00\x00"
            return (
                bytes([resp_pdu])
                + tx_id.to_bytes(2, byteorder="big")
                + len(params).to_bytes(2, byteorder="big")
                + params
            )

    def close(self) -> None:
        pass


@pytest.fixture
def mock_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock discovery backend to return a fixed set of devices."""

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [
            Device(name="Mock Device A", mac_address="11:22:33:44:55:66"),
            Device(name="Mock Device B", mac_address="AA:BB:CC:DD:EE:FF"),
        ]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)


# 10.2: Write integration tests for complete discovery -> probe -> fuzz -> crash workflow
# 10.4: Write integration tests for crash detection with simulated crash behavior
def test_e2e_discovery_probe_fuzz_crash(
    mock_devices, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = MockSDPServerState(
        services=[b"\x35\x03ServicePart1", b"\x35\x03ServicePart2"],
        continuation_states=[b"\x01\x02", b""],
        crash_after_packets=5,
    )

    monkeypatch.setattr(
        "sdpfuzz2.cli.L2CAPTransport",
        lambda *args, **kwargs: MockSDPServerTransport(state, *args, **kwargs),
    )

    log_file = tmp_path / "fuzz_e2e_run.json"

    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--output", str(log_file)], input="2\n1\n")

    assert result.exit_code == 2
    assert "Session stopped due to crash detection" in result.stdout
    assert "SDP probe completed successfully" in result.stdout

    # 10.6: Write integration tests for JSON log output and schema validation
    assert log_file.exists()
    with open(log_file, encoding="utf-8") as f:
        log_data = json.load(f)

    session = FuzzingSession(**log_data)
    assert session.device_name == "Mock Device B"
    assert session.device_mac_address == "AA:BB:CC:DD:EE:FF"
    assert len(session.logs) > 5
    assert any(log.crash == 1 for log in session.logs)


# 10.3: Write integration tests for all four fuzzing modes
@pytest.mark.parametrize(
    "mode", ["random-bytes", "continuation-length", "continuation-bytes", "random-mutation"]
)
def test_e2e_fuzzing_modes(mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = MockSDPServerState(
        services=[b"\x35\x03ServicePart1", b"\x35\x03ServicePart2"],
        continuation_states=[b"\x01\x02", b""],
        crash_after_packets=5,
    )

    monkeypatch.setattr(
        "sdpfuzz2.cli.L2CAPTransport",
        lambda *args, **kwargs: MockSDPServerTransport(state, *args, **kwargs),
    )

    log_file = tmp_path / f"fuzz_e2e_{mode}.json"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fuzz",
            "--target",
            "11:22:33:44:55:66",
            "--mode",
            mode,
            "--output",
            str(log_file),
        ],
    )

    assert result.exit_code == 2
    assert "Session stopped due to crash detection" in result.stdout

    with open(log_file, encoding="utf-8") as f:
        log_data = json.load(f)
    session = FuzzingSession(**log_data)
    assert session.fuzz_mode == mode
    assert len(session.logs) > 5
    assert any(log.crash == 1 for log in session.logs)


# 10.5: Write integration tests for concurrent fuzzing with multiple workers
def test_e2e_concurrent_fuzzing_multiple_workers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = MockSDPServerState(
        services=[b"\x35\x03ServicePart1", b"\x35\x03ServicePart2"],
        continuation_states=[b"\x01\x02", b""],
        crash_after_packets=10,
    )

    monkeypatch.setattr(
        "sdpfuzz2.cli.L2CAPTransport",
        lambda *args, **kwargs: MockSDPServerTransport(state, *args, **kwargs),
    )

    log_file = tmp_path / "fuzz_e2e_concurrent.json"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fuzz",
            "--target",
            "11:22:33:44:55:66",
            "--mode",
            "random-bytes",
            "--concurrency",
            "3",
            "--queue-size",
            "16",
            "--output",
            str(log_file),
        ],
    )

    assert result.exit_code == 2
    assert "Session stopped due to crash detection" in result.stdout

    with open(log_file, encoding="utf-8") as f:
        log_data = json.load(f)
    session = FuzzingSession(**log_data)
    assert len(session.logs) > 10
    assert any(log.crash == 1 for log in session.logs)
