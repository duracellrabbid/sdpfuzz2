import platform
from typing import Any

import pytest

from sdpfuzz2.bluetooth.discovery import (
    BLUEZ_DEVICE_INTERFACE,
    BlueZDiscoveryBackend,
    DiscoveryBackend,
    DiscoveryError,
    DiscoveryService,
    NoopDiscoveryBackend,
    RawDiscoveredDevice,
    normalize_discovered_devices,
)


class FakeBackend(DiscoveryBackend):
    def __init__(self, devices: list[RawDiscoveredDevice]) -> None:
        self._devices = devices

    def scan(self) -> list[RawDiscoveredDevice]:
        return self._devices


class FakeBlueZClient:
    def __init__(self, managed_objects: dict[str, dict[str, dict[str, Any]]]) -> None:
        self._managed_objects = managed_objects
        self.last_timeout: float | None = None

    def scan_managed_objects(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:
        self.last_timeout = timeout_seconds
        return self._managed_objects


class ExplodingBlueZClient:
    def scan_managed_objects(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:
        del timeout_seconds
        raise RuntimeError("dbus call failed")


def test_discovery_normalizes_and_filters_devices() -> None:
    backend = FakeBackend(
        devices=[
            RawDiscoveredDevice(name="  Headset  ", mac_address="aa:bb:cc:dd:ee:ff"),
            RawDiscoveredDevice(name="", mac_address="11:22:33:44:55:66"),
            RawDiscoveredDevice(name="Speaker", mac_address="invalid-mac"),
            RawDiscoveredDevice(name="Duplicate", mac_address="AA:BB:CC:DD:EE:FF"),
        ]
    )

    discovered = DiscoveryService(backend).discover(include_unnamed=False)

    assert len(discovered) == 1
    assert discovered[0].name == "Headset"
    assert discovered[0].mac_address == "AA:BB:CC:DD:EE:FF"


def test_discovery_can_include_unnamed_devices() -> None:
    backend = FakeBackend(
        devices=[
            RawDiscoveredDevice(name=None, mac_address="11:22:33:44:55:66"),
            RawDiscoveredDevice(name="  ", mac_address="22:33:44:55:66:77"),
        ]
    )

    discovered = DiscoveryService(backend).discover(include_unnamed=True)

    assert len(discovered) == 2
    assert discovered[0].name == "Unknown Device"
    assert discovered[1].name == "Unknown Device"


def test_normalize_discovered_devices_helper() -> None:
    discovered = normalize_discovered_devices(
        [RawDiscoveredDevice(name="Mouse", mac_address="00:11:22:33:44:55")]
    )

    assert len(discovered) == 1
    assert discovered[0].name == "Mouse"
    assert discovered[0].mac_address == "00:11:22:33:44:55"


def test_bluez_backend_maps_devices_from_managed_objects() -> None:
    managed_objects = {
        "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF": {
            BLUEZ_DEVICE_INTERFACE: {
                "Address": "AA:BB:CC:DD:EE:FF",
                "Name": "Speaker",
            }
        },
        "/org/bluez/hci0/dev_11_22_33_44_55_66": {
            BLUEZ_DEVICE_INTERFACE: {
                "Address": "11:22:33:44:55:66",
                "Alias": "Controller",
            }
        },
        "/org/bluez/hci0/dev_missing_address": {
            BLUEZ_DEVICE_INTERFACE: {
                "Name": "Ignored",
            }
        },
    }
    client = FakeBlueZClient(managed_objects)

    devices = BlueZDiscoveryBackend(client, scan_timeout_seconds=1.5).scan()

    assert client.last_timeout == 1.5
    assert devices == [
        RawDiscoveredDevice(name="Speaker", mac_address="AA:BB:CC:DD:EE:FF"),
        RawDiscoveredDevice(name="Controller", mac_address="11:22:33:44:55:66"),
    ]


def test_bluez_backend_wraps_client_failures() -> None:
    with pytest.raises(DiscoveryError, match="BlueZ D-Bus discovery failed"):
        BlueZDiscoveryBackend(ExplodingBlueZClient()).scan()


def test_discovery_service_returns_empty_on_discovery_error() -> None:
    service = DiscoveryService(backend=BlueZDiscoveryBackend(ExplodingBlueZClient()))

    assert service.discover() == []


def test_default_backend_linux_uses_bluez(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2 import bluetooth

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    backend = bluetooth.discovery._default_backend()

    assert isinstance(backend, BlueZDiscoveryBackend)


def test_default_backend_non_linux_uses_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2 import bluetooth

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    backend = bluetooth.discovery._default_backend()

    assert isinstance(backend, NoopDiscoveryBackend)
