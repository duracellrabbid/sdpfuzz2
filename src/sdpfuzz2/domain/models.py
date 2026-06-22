"""Core domain models for run logging and target metadata."""

import re
from dataclasses import asdict, dataclass

MAC_ADDRESS_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _ensure_valid_mac(value: str) -> str:
    """Validate a colon-separated Bluetooth MAC address."""
    if not MAC_ADDRESS_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid MAC address: {value}")
    return value


@dataclass(frozen=True)
class Device:
    """Represents a discovered Bluetooth device.

    `name` is the user-facing label shown in the CLI and `mac_address` is the
    normalized Bluetooth target address used by transports.
    """

    name: str
    mac_address: str

    def __post_init__(self) -> None:
        _ensure_valid_mac(self.mac_address)


@dataclass(frozen=True)
class PacketLogEntry:
    """One request/response pair logged during fuzzing.

    `crash` is stored as `0` or `1` to keep the serialized log schema compact
    and stable for downstream tooling.
    """

    request_packet_hex: str
    response_packet_hex: str
    crash: int

    def __post_init__(self) -> None:
        if self.crash not in (0, 1):
            raise ValueError("crash must be 0 or 1")


@dataclass(frozen=True)
class RunLog:
    """Top-level run log schema.

    The log captures the target device identity, the run start time, and the
    ordered packet exchange history for the session.
    """

    device_name: str
    device_mac_address: str
    start_time: str
    logs: list[PacketLogEntry]

    def __post_init__(self) -> None:
        _ensure_valid_mac(self.device_mac_address)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dictionary representation."""
        return asdict(self)
