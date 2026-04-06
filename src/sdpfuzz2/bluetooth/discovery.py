"""Bluetooth discovery abstraction."""

from collections.abc import Sequence

from sdpfuzz2.domain.models import Device


class DiscoveryService:
    """Discovery interface; implementation is added in later phases."""

    def discover(self) -> Sequence[Device]:
        """Return discovered Bluetooth devices."""
        return []
