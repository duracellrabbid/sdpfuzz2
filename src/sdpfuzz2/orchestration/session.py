"""Session state placeholder."""

from dataclasses import dataclass


@dataclass
class FuzzSession:
    """Represents one fuzzing session configuration."""

    target_mac: str
    mode: str
