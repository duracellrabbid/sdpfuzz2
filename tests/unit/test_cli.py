import pytest
import typer
from typer.testing import CliRunner

from sdpfuzz2.bluetooth.probe import ProbeResult
from sdpfuzz2.cli import app, select_target_device
from sdpfuzz2.domain.errors import TransportError
from sdpfuzz2.domain.models import Device


def test_version_command_returns_package_version() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_select_target_device_with_explicit_index() -> None:
    devices = [
        Device(name="Alpha", mac_address="00:11:22:33:44:55"),
        Device(name="Beta", mac_address="AA:BB:CC:DD:EE:FF"),
    ]

    selected = select_target_device(devices, selected_index=2)

    assert selected == devices[1]


def test_select_target_device_rejects_out_of_range_index() -> None:
    devices = [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    with pytest.raises(typer.BadParameter, match="Target index must be between 1 and 1"):
        select_target_device(devices, selected_index=2)


def test_discover_command_uses_option_index(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [
            Device(name="Alpha", mac_address="00:11:22:33:44:55"),
            Device(name="Beta", mac_address="AA:BB:CC:DD:EE:FF"),
        ]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover", "--index", "2"])

    assert result.exit_code == 0
    assert "[1] Alpha - 00:11:22:33:44:55" in result.stdout
    assert "[2] Beta - AA:BB:CC:DD:EE:FF" in result.stdout
    assert "Selected target: Beta (AA:BB:CC:DD:EE:FF)" in result.stdout


def test_discover_command_interactive_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover"], input="1\n")

    assert result.exit_code == 0
    assert "Selected target: Alpha (00:11:22:33:44:55)" in result.stdout


def test_discover_command_no_devices_returns_non_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover"])

    assert result.exit_code == 1
    assert "No discoverable named devices found" in result.stdout


def test_probe_command_uses_selected_target_and_prints_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
        assert target.mac_address == "00:11:22:33:44:55"
        assert response_timeout_ms == 900
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02", b"\x09\x00\x01"],
            continuation_states=[b"\x01\x02"],
        )

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe_selected_target)

    result = runner.invoke(app, ["probe", "--index", "1", "--response-timeout-ms", "900"])

    assert result.exit_code == 0
    assert "Selected target: Alpha (00:11:22:33:44:55)" in result.stdout
    assert "Starting SDP probe for 00:11:22:33:44:55..." in result.stdout
    assert "SDP probe completed" in result.stdout
    assert "Attribute pages collected: 2" in result.stdout
    assert "Continuation states collected: 1" in result.stdout
    assert "Combined attribute payload bytes: 5" in result.stdout


def test_probe_command_returns_non_zero_when_transport_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
        del target
        del response_timeout_ms
        raise TransportError("connect failed")

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe_selected_target)

    result = runner.invoke(app, ["probe", "--index", "1"])

    assert result.exit_code == 1
    assert "Probe transport failed: connect failed" in result.stdout
