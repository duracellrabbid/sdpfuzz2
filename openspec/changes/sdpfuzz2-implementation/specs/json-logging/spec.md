## ADDED Requirements

### Requirement: JSON Log Schema
The system SHALL log all fuzzing activity in structured JSON format.

#### Scenario: Log contains device information
- **WHEN** fuzzing session begins
- **THEN** log includes device_name of target
- **THEN** log includes device_mac_address of target
- **THEN** log includes start_time in ISO 8601 UTC format

#### Scenario: Log entry for each packet
- **WHEN** packet is sent to target
- **THEN** system creates log entry with request_packet_hex containing hex-encoded request bytes
- **WHEN** response is received
- **THEN** system adds response_packet_hex containing hex-encoded response bytes to same entry
- **THEN** system marks crash status (0 for no crash, 1 for crash)

#### Scenario: Packet indexing in logs
- **WHEN** packet N is sent
- **THEN** log entry includes packet_index field with value N
- **THEN** logs can be sorted by packet_index to show execution order
- **THEN** log entries for out-of-order responses remain correctly indexed

### Requirement: Incremental Log Writing
The system SHALL write logs incrementally with periodic flushing.

#### Scenario: Logs flushed periodically
- **WHEN** fuzzing session is active
- **THEN** system writes log entries to file periodically (e.g., every 100 packets or every 5 seconds)
- **THEN** user can monitor logs in real-time without waiting for session completion

#### Scenario: Final flush on session termination
- **WHEN** fuzzing session terminates
- **THEN** system flushes all remaining log entries
- **THEN** final log file contains all packets sent and responses received

### Requirement: Crash-Safe Writes
The system SHALL use atomic operations to prevent log corruption.

#### Scenario: Atomic log writes prevent corruption
- **WHEN** system writes log entries
- **THEN** system uses atomic file operations (e.g., write to temporary file then rename)
- **THEN** partial writes do not corrupt log file

#### Scenario: Log integrity after unexpected termination
- **WHEN** fuzzing session is terminated unexpectedly (crash, forced stop)
- **THEN** log file remains valid and can be parsed
- **THEN** all flushed entries are recoverable
- **THEN** in-flight entries not yet flushed may be lost (acceptable trade-off)

### Requirement: Log Metadata
The system SHALL include metadata in logs for analysis and debugging.

#### Scenario: Extended log schema
- **WHEN** fuzzing session is active
- **THEN** log may include fuzz_mode field (e.g., "random-bytes", "continuation-length")
- **THEN** log may include run_id for identifying session
- **THEN** log may include end_time in ISO 8601 UTC format
- **THEN** log may include summary_counters (packets_sent, packets_received, crashes_detected)

#### Scenario: Worker metadata in entries
- **WHEN** packet is sent by worker
- **THEN** log entry may include worker_id identifying source worker
- **THEN** log entry may include in_flight_at_send indicating concurrent requests

### Requirement: JSON Schema Validation
The system SHALL validate log schema on write.

#### Scenario: Required fields present
- **WHEN** log entry is created
- **THEN** system validates required fields are present and non-null
- **THEN** system rejects entry if required fields missing

#### Scenario: Type validation
- **WHEN** log entry is written
- **THEN** system validates all field types match schema
- **THEN** system converts values to correct types (e.g., hex string for packets)
