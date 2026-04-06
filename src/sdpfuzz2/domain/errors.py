"""Project-specific exception types."""


class SDPFuzzError(Exception):
    """Base exception for SDPFuzz2."""


class TransportError(SDPFuzzError):
    """Raised when Bluetooth transport operations fail."""


class PacketParseError(SDPFuzzError):
    """Raised when SDP packet parsing fails."""
