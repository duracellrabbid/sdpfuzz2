"""Run log writer."""

import datetime
import json
import threading
import time
from pathlib import Path

from sdpfuzz2.logging.schema import FuzzingSession, RequestResponseLog, SummaryCounters


class RunLogger:
    """Persists run logs in JSON format incrementally and atomically."""

    def __init__(
        self,
        output_path: Path,
        device_name: str = "Unknown Device",
        device_mac_address: str = "00:00:00:00:00:00",
        start_time: str | None = None,
        fuzz_mode: str | None = None,
        run_id: str | None = None,
        flush_interval_seconds: float = 5.0,
        flush_interval_packets: int = 100,
    ) -> None:
        """Initialize the logger with destination and metadata."""
        self.output_path = output_path
        self.device_name = device_name
        self.device_mac_address = device_mac_address

        # Validate MAC address
        FuzzingSession._validate_mac_address(device_mac_address)

        if start_time is None:
            self.start_time = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        else:
            self.start_time = start_time

        self.fuzz_mode = fuzz_mode
        self.run_id = run_id
        self.end_time: str | None = None

        self.flush_interval_seconds = flush_interval_seconds
        self.flush_interval_packets = flush_interval_packets

        self._logs_dict: dict[int, RequestResponseLog] = {}
        self._last_flush_time = time.time()
        self._unsaved_packets_count = 0
        self._lock = threading.Lock()

    def log_request(
        self,
        packet_index: int,
        payload: bytes | str,
        in_flight_at_send: int | None = None,
        worker_id: int | None = None,
    ) -> None:
        """Record a request packet send."""
        if isinstance(payload, bytes):
            payload_hex = payload.hex()
        else:
            payload_hex = str(payload)

        with self._lock:
            # Re-create/validate the entry
            entry = RequestResponseLog(
                request_packet_hex=payload_hex,
                response_packet_hex="",
                crash=0,
                packet_index=packet_index,
                worker_id=worker_id,
                in_flight_at_send=in_flight_at_send,
            )
            self._logs_dict[packet_index] = entry
            self._unsaved_packets_count += 1
            self._check_flush_under_lock()

    def log_response(
        self,
        packet_index: int,
        response_payload: bytes | str | None,
        crash: int,
        worker_id: int | None = None,
    ) -> None:
        """Record a response packet receive."""
        if response_payload is None:
            resp_hex = ""
        elif isinstance(response_payload, bytes):
            resp_hex = response_payload.hex()
        else:
            resp_hex = str(response_payload)

        with self._lock:
            if packet_index in self._logs_dict:
                entry = self._logs_dict[packet_index]
                updated_entry = RequestResponseLog(
                    request_packet_hex=entry.request_packet_hex,
                    response_packet_hex=resp_hex,
                    crash=crash,
                    packet_index=packet_index,
                    worker_id=worker_id if worker_id is not None else entry.worker_id,
                    in_flight_at_send=entry.in_flight_at_send,
                )
            else:
                updated_entry = RequestResponseLog(
                    request_packet_hex="",
                    response_packet_hex=resp_hex,
                    crash=crash,
                    packet_index=packet_index,
                    worker_id=worker_id,
                    in_flight_at_send=None,
                )
            self._logs_dict[packet_index] = updated_entry
            self._unsaved_packets_count += 1
            self._check_flush_under_lock()

    def _check_flush_under_lock(self) -> None:
        elapsed = time.time() - self._last_flush_time
        if (
            self._unsaved_packets_count >= self.flush_interval_packets
            or elapsed >= self.flush_interval_seconds
        ):
            self._flush_under_lock()

    def flush(self) -> None:
        """Force write all in-memory entries to disk atomically."""
        with self._lock:
            self._flush_under_lock()

    def _flush_under_lock(self) -> None:
        sorted_logs = sorted(self._logs_dict.values(), key=lambda e: e.packet_index or 0)
        session = FuzzingSession(
            device_name=self.device_name,
            device_mac_address=self.device_mac_address,
            start_time=self.start_time,
            logs=sorted_logs,
            fuzz_mode=self.fuzz_mode,
            run_id=self.run_id,
            end_time=self.end_time,
            summary_counters=self.summary_counters,
        )
        self._write_session_atomically(session)
        self._last_flush_time = time.time()
        self._unsaved_packets_count = 0

    def finalize(self) -> None:
        """Mark session end time and flush remaining logs."""
        with self._lock:
            self.end_time = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
            self._flush_under_lock()

    @property
    def summary_counters(self) -> SummaryCounters:
        """Compute summary counters based on current logs in memory."""
        packets_sent = len(self._logs_dict)
        packets_received = sum(1 for e in self._logs_dict.values() if e.response_packet_hex)
        crashes_detected = sum(1 for e in self._logs_dict.values() if e.crash == 1)
        return SummaryCounters(
            packets_sent=packets_sent,
            packets_received=packets_received,
            crashes_detected=crashes_detected,
        )

    def _write_session_atomically(self, session: FuzzingSession) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.output_path.with_suffix(self.output_path.suffix + ".tmp")
        try:
            data = session.model_dump(exclude_none=True)
            temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temp_path.replace(self.output_path)
        except Exception as exc:
            if temp_path.exists():
                temp_path.unlink()
            raise exc

    def write(self, run_log: object) -> None:
        """Backward compatibility write method for snapshot serialization."""
        from typing import Any, cast

        if not isinstance(run_log, FuzzingSession):
            if hasattr(run_log, "to_dict"):
                log_data = run_log.to_dict()
            elif hasattr(run_log, "__dict__"):
                log_data = {k: v for k, v in run_log.__dict__.items()}
            else:
                log_data = dict(cast(Any, run_log))

            # Convert inner logs to RequestResponseLog/LogEntry
            if "logs" in log_data and isinstance(log_data["logs"], list):
                converted_logs = []
                for entry in log_data["logs"]:
                    if not isinstance(entry, RequestResponseLog):
                        if hasattr(entry, "to_dict"):
                            entry_data = entry.to_dict()
                        elif hasattr(entry, "__dict__"):
                            entry_data = {k: v for k, v in entry.__dict__.items()}
                        elif isinstance(entry, dict):
                            entry_data = entry
                        else:
                            entry_data = dict(cast(Any, entry))
                        converted_logs.append(RequestResponseLog(**entry_data))
                    else:
                        converted_logs.append(entry)
                log_data["logs"] = converted_logs

            session = FuzzingSession(**log_data)
        else:
            session = run_log

        self._write_session_atomically(session)
