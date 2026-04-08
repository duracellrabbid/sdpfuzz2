"""Bluetooth discovery abstraction."""

import asyncio
import platform
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from sdpfuzz2.domain.models import Device

UNKNOWN_DEVICE_NAME = "Unknown Device"
BLUEZ_DEVICE_INTERFACE = "org.bluez.Device1"
BLUEZ_ADAPTER_INTERFACE = "org.bluez.Adapter1"


class DiscoveryError(RuntimeError):
    """Raised when discovery backend operations fail."""


@dataclass(frozen=True)
class RawDiscoveredDevice:
    """Raw discovered device prior to normalization."""

    name: str | None
    mac_address: str


class DiscoveryBackend(Protocol):
    """Backend contract for platform-specific Bluetooth discovery."""

    def scan(self) -> Sequence[RawDiscoveredDevice]:
        """Return discovered devices from a platform adapter."""


class BlueZDBusClient(Protocol):
    """Contract for BlueZ D-Bus operations used by discovery."""

    def scan_managed_objects(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:
        """Return BlueZ managed objects after a bounded discovery scan."""


class NoopDiscoveryBackend:
    """Default backend used in non-Linux development and tests."""

    def scan(self) -> Sequence[RawDiscoveredDevice]:
        """Return an empty scan result."""
        return []


class BlueZDiscoveryBackend:
    """Linux discovery backend that queries BlueZ over D-Bus."""

    def __init__(
        self,
        client: BlueZDBusClient | None = None,
        *,
        scan_timeout_seconds: float = 2.0,
    ) -> None:
        self._client = client or DBusNextBlueZClient()
        self._scan_timeout_seconds = scan_timeout_seconds

    def scan(self) -> Sequence[RawDiscoveredDevice]:
        """Scan BlueZ managed objects and map Device1 entries into raw devices."""
        try:
            managed_objects = self._client.scan_managed_objects(self._scan_timeout_seconds)
        except Exception as error:  # pragma: no cover - exercised by unit tests via mock client
            raise DiscoveryError("BlueZ D-Bus discovery failed") from error

        devices: list[RawDiscoveredDevice] = []
        for object_payload in managed_objects.values():
            device_properties = object_payload.get(BLUEZ_DEVICE_INTERFACE)
            if not device_properties:
                continue

            mac_address = _coerce_optional_str(_unwrap_dbus_value(device_properties.get("Address")))
            if not mac_address:
                continue

            name_value = _unwrap_dbus_value(device_properties.get("Name"))
            alias_value = _unwrap_dbus_value(device_properties.get("Alias"))
            name = _coerce_optional_str(name_value) or _coerce_optional_str(alias_value)

            devices.append(RawDiscoveredDevice(name=name, mac_address=mac_address))

        return devices


class DBusNextBlueZClient:
    """dbus-next implementation for querying BlueZ managed objects."""

    def scan_managed_objects(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:  # pragma: no cover
        try:
            return asyncio.run(self._scan_managed_objects_async(timeout_seconds))
        except ImportError as error:
            raise DiscoveryError("dbus-next is not available") from error

    async def _scan_managed_objects_async(
        self, timeout_seconds: float
    ) -> dict[str, dict[str, dict[str, object]]]:  # pragma: no cover
        from dbus_next import BusType  # type: ignore[import-not-found]
        from dbus_next.aio import MessageBus  # type: ignore[import-not-found]

        bus = MessageBus(bus_type=BusType.SYSTEM)
        await bus.connect()

        bluez_root = "/"
        bluez_service = "org.bluez"

        root_introspection = await bus.introspect(bluez_service, bluez_root)
        root_object = bus.get_proxy_object(bluez_service, bluez_root, root_introspection)
        object_manager = root_object.get_interface("org.freedesktop.DBus.ObjectManager")

        before_scan = await object_manager.call_get_managed_objects()
        adapter_path = self._find_adapter_path(before_scan)

        if adapter_path is not None:
            adapter_introspection = await bus.introspect(bluez_service, adapter_path)
            adapter_object = bus.get_proxy_object(
                bluez_service,
                adapter_path,
                adapter_introspection,
            )
            adapter = adapter_object.get_interface(BLUEZ_ADAPTER_INTERFACE)

            await adapter.call_start_discovery()
            await asyncio.sleep(max(0.0, timeout_seconds))
            await adapter.call_stop_discovery()

        managed_objects = await object_manager.call_get_managed_objects()
        if hasattr(bus, "disconnect"):
            bus.disconnect()

        return _to_plain_object_map(managed_objects)

    def _find_adapter_path(self, managed_objects: object) -> str | None:  # pragma: no cover
        for object_path, interfaces in _iter_managed_items(managed_objects):
            if BLUEZ_ADAPTER_INTERFACE in interfaces:
                return object_path
        return None


def _normalize_name(name: str | None) -> str:
    normalized = (name or "").strip()
    return normalized or UNKNOWN_DEVICE_NAME


def _normalize_mac_address(mac_address: str) -> str:
    return mac_address.strip().upper()


class DiscoveryService:
    """Discover and normalize Bluetooth devices."""

    def __init__(self, backend: DiscoveryBackend | None = None) -> None:
        self._backend = backend or _default_backend()

    def discover(self, *, include_unnamed: bool = False) -> list[Device]:
        """Return normalized Bluetooth devices, optionally including unnamed targets."""
        normalized_devices: list[Device] = []
        seen_macs: set[str] = set()

        try:
            raw_devices = self._backend.scan()
        except DiscoveryError:
            return []

        for raw_device in raw_devices:
            name = _normalize_name(raw_device.name)
            mac_address = _normalize_mac_address(raw_device.mac_address)

            if not include_unnamed and name == UNKNOWN_DEVICE_NAME:
                continue
            if mac_address in seen_macs:
                continue

            try:
                device = Device(name=name, mac_address=mac_address)
            except ValueError:
                continue

            normalized_devices.append(device)
            seen_macs.add(mac_address)

        return normalized_devices


def normalize_discovered_devices(
    devices: Iterable[RawDiscoveredDevice], *, include_unnamed: bool = False
) -> list[Device]:
    """Normalize externally supplied discovery entries into domain devices."""
    service = DiscoveryService(backend=NoopDiscoveryBackend())
    # Reuse filtering logic by evaluating through an ephemeral backend object.
    service._backend = _EphemeralBackend(list(devices))
    return service.discover(include_unnamed=include_unnamed)


class _EphemeralBackend:
    def __init__(self, devices: Sequence[RawDiscoveredDevice]) -> None:
        self._devices = devices

    def scan(self) -> Sequence[RawDiscoveredDevice]:
        return self._devices


def _default_backend() -> DiscoveryBackend:
    if platform.system() == "Linux":
        return BlueZDiscoveryBackend()
    return NoopDiscoveryBackend()


def _coerce_optional_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _unwrap_dbus_value(value: object) -> object:
    if hasattr(value, "value"):
        return value.value
    return value


def _iter_managed_items(
    managed_objects: object,
) -> list[tuple[str, dict[str, object]]]:  # pragma: no cover
    if not isinstance(managed_objects, dict):
        return []

    items: list[tuple[str, dict[str, object]]] = []
    for object_path, interface_map in managed_objects.items():
        if not isinstance(object_path, str) or not isinstance(interface_map, dict):
            continue
        items.append((object_path, interface_map))
    return items


def _to_plain_object_map(
    managed_objects: object,
) -> dict[str, dict[str, dict[str, object]]]:  # pragma: no cover
    plain_map: dict[str, dict[str, dict[str, object]]] = {}
    for object_path, interface_map in _iter_managed_items(managed_objects):
        interfaces: dict[str, dict[str, object]] = {}
        for interface_name, props in interface_map.items():
            if not isinstance(interface_name, str) or not isinstance(props, dict):
                continue
            plain_props: dict[str, object] = {}
            for key, value in props.items():
                if isinstance(key, str):
                    plain_props[key] = _unwrap_dbus_value(value)
            interfaces[interface_name] = plain_props
        plain_map[object_path] = interfaces
    return plain_map
