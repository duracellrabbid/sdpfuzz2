"""Pydantic models for run-log schema validation."""

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


class SummaryCounters(BaseModel):
    """Counters summarizing the fuzzer session execution."""

    packets_sent: int = 0
    packets_received: int = 0
    crashes_detected: int = 0


class RequestResponseLog(BaseModel):
    """One request/response observation in a fuzzing session."""

    model_config = ConfigDict(extra="forbid")

    request_packet_hex: str
    response_packet_hex: str = ""
    crash: int = Field(default=0, ge=0, le=1)
    packet_index: int | None = None
    worker_id: int | None = None
    in_flight_at_send: int | None = None

    @field_validator("request_packet_hex", "response_packet_hex")
    @classmethod
    def _validate_hex_field(cls, value: str) -> str:
        if not _HEX_RE.fullmatch(value):
            raise ValueError("packet hex fields must contain only hexadecimal characters")
        return value


class LogEntry(RequestResponseLog):
    """Compatibility name for a single run-log entry."""


class FuzzingSession(BaseModel):
    """Top-level JSON schema for one fuzzing run."""

    model_config = ConfigDict(extra="forbid")

    device_name: str
    device_mac_address: str
    start_time: str
    logs: list[RequestResponseLog]
    fuzz_mode: str | None = None
    run_id: str | None = None
    end_time: str | None = None
    summary_counters: SummaryCounters | None = None

    @field_validator("device_mac_address")
    @classmethod
    def _validate_mac_address(cls, value: str) -> str:
        if not _MAC_RE.fullmatch(value):
            raise ValueError("device_mac_address must be a valid MAC address")
        return value


# Backward-compatible aliases used by earlier scaffolding tests/imports.
PacketLogEntry = LogEntry
RunLog = FuzzingSession


__all__ = [
    "LogEntry",
    "FuzzingSession",
    "RequestResponseLog",
    "PacketLogEntry",
    "RunLog",
    "SummaryCounters",
]
