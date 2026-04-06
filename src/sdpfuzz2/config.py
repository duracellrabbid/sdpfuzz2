"""Runtime configuration models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeConfig:
    """Runtime defaults for initial scaffolding."""

    concurrency: int = 1
    queue_size: int = 64
    response_timeout_ms: int = 1500
