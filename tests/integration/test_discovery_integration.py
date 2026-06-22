"""Integration tests for device discovery end-to-end flow with a mock backend.

These tests exercise the full pipeline from DiscoveryService through the CLI
using a deterministic fake backend that simulates what a real Bluetooth
environment would return.
"""

from collections.abc import Sequence

import pytest
from typer.testing import CliRunner

from sdpfuzz2.bluetooth.discovery import (
    DiscoveryService,
    NoopDiscoveryBackend,
    RawDiscoveredDevice,
)
from sdpfuzz2.cli import app
from sdpfuzz2.domain.models import Device


class _MockSdpServerBackend:
    """Simulates devices as they appear when a host with SDP services is nearby."""

    def __init__(self, devices: list[RawDiscoveredDevice]) -> None:
        self._devices = devices

    def scan(self) -> Sequence[RawDiscoveredDevice]:
        return list(self._devices)


_REALISTIC_DEVICES = [
    RawDiscoveredDevice(name="Headset Pro", mac_address="AA:BB:CC:DD:EE:01"),
    RawDiscoveredDevice(name="Smart Speaker", mac_address="AA:BB:CC:DD:EE:02"),
    RawDiscoveredDevice(name=None, mac_address="AA:BB:CC:DD:EE:03"),  # unnamed
    RawDiscoveredDevice(name="  Keyboard  ", mac_address="AA:BB:CC:DD:EE:04"),  # padded name
    RawDiscoveredDevice(name="Headset Pro", mac_address="AA:BB:CC:DD:EE:01"),  # duplicate MAC
]


def test_discovery_service_returns_normalised_unique_named_devices() -> None:
    service = DiscoveryService(_MockSdpServerBackend(_REALISTIC_DEVICES))

    devices = service.discover(include_unnamed=False)

    names = [d.name for d in devices]
    macs = [d.mac_address for d in devices]

    assert "Headset Pro" in names
    assert "Smart Speaker" in names
    assert "Keyboard" in names  # whitespace stripped
    assert "Unknown Device" not in names  # unnamed filtered out
    assert len(devices) == 3  # duplicate MAC deduplicated
    assert len(set(macs)) == len(macs)  # all MACs unique


def test_discovery_service_includes_unnamed_when_requested() -> None:
    service = DiscoveryService(_MockSdpServerBackend(_REALISTIC_DEVICES))

    devices = service.discover(include_unnamed=True)

    names = [d.name for d in devices]
    assert "Unknown Device" in names
    assert len(devices) == 4  # still deduplicates by MAC


def test_discovery_service_returns_empty_for_no_devices() -> None:
    service = DiscoveryService(_MockSdpServerBackend([]))

    devices = service.discover()

    assert devices == []


def test_discovery_service_returns_empty_for_noop_backend() -> None:
    service = DiscoveryService(NoopDiscoveryBackend())

    devices = service.discover()

    assert devices == []


def test_cli_discover_command_displays_all_named_devices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [
            Device(name="Headset Pro", mac_address="AA:BB:CC:DD:EE:01"),
            Device(name="Smart Speaker", mac_address="AA:BB:CC:DD:EE:02"),
            Device(name="Keyboard", mac_address="AA:BB:CC:DD:EE:04"),
        ]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover", "--index", "1"])

    assert result.exit_code == 0
    assert "Headset Pro" in result.stdout
    assert "AA:BB:CC:DD:EE:01" in result.stdout
    assert "Smart Speaker" in result.stdout
    assert "Keyboard" in result.stdout
    assert "Selected target: Headset Pro (AA:BB:CC:DD:EE:01)" in result.stdout


def test_cli_discover_command_selects_last_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [
            Device(name="Headset Pro", mac_address="AA:BB:CC:DD:EE:01"),
            Device(name="Smart Speaker", mac_address="AA:BB:CC:DD:EE:02"),
        ]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover", "--index", "2"])

    assert result.exit_code == 0
    assert "Selected target: Smart Speaker (AA:BB:CC:DD:EE:02)" in result.stdout


def test_cli_discover_command_rejects_out_of_range_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Headset Pro", mac_address="AA:BB:CC:DD:EE:01")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover", "--index", "5"])

    assert result.exit_code != 0


def test_cli_discover_command_exits_when_no_devices_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover"])

    assert result.exit_code == 1
    assert "No discoverable named devices found" in result.stdout
