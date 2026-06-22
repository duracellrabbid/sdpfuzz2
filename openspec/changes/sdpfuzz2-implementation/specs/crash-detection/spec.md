## ADDED Requirements

### Requirement: Timeout-Based Crash Detection
The system SHALL detect crashes when target stops responding within configured timeout threshold.

#### Scenario: Consecutive timeouts indicate crash
- **WHEN** target fails to respond to N consecutive fuzzing packets within timeout period
- **THEN** system increments timeout counter
- **THEN** when counter reaches configured threshold (e.g., 3-5 timeouts)
- **THEN** system declares crash with medium confidence

#### Scenario: Single successful response resets timeout counter
- **WHEN** target responds successfully to packet after previous timeouts
- **THEN** system resets timeout counter to zero

### Requirement: Connection Failure-Based Crash Detection
The system SHALL detect crashes when target connection state changes unexpectedly.

#### Scenario: Connection refused after prior success
- **WHEN** target was previously responsive
- **THEN** system attempts connection and receives connection refused or reset
- **THEN** system logs as potential crash signal

#### Scenario: Repeated connection failures confirm crash
- **WHEN** connection failures occur repeatedly across multiple workers
- **THEN** system calculates confidence score based on worker corroboration
- **THEN** if confidence threshold met, system declares high-confidence crash

### Requirement: HCI Error Classification
The system SHALL classify and log HCI-level errors for crash attribution.

#### Scenario: Local adapter error detected
- **WHEN** system encounters HCI adapter error (power failure, driver issue)
- **THEN** system classifies as local environment issue, not target crash
- **THEN** system does not halt fuzzing based on local errors alone

#### Scenario: Remote device error detected
- **WHEN** system receives remote device error from target
- **THEN** system classifies as potential crash signal
- **THEN** system includes error in crash confidence calculation

### Requirement: Control Probe Validation
The system SHALL validate crash signals using control probes.

#### Scenario: Send control probe after worker failure
- **WHEN** worker detects potential crash signal
- **THEN** system sends known-good SDP packet (control probe)
- **WHEN** control probe fails but other communication channels active
- **THEN** confidence of crash detection increases

#### Scenario: Worker corroboration
- **WHEN** multiple workers detect crash signals simultaneously
- **THEN** system increases crash confidence score based on worker agreement
- **THEN** requires corroboration before declaring high-confidence crash

### Requirement: Crash Confidence Reporting
The system SHALL report crash detection with confidence level and reason.

#### Scenario: Log crash event with confidence and reason
- **WHEN** crash is detected
- **THEN** system logs crash event with confidence level (high/medium/unknown)
- **THEN** system includes reason (e.g., "N consecutive timeouts", "connection reset")
- **THEN** system includes number of workers detecting signal
- **THEN** user can review logs to understand crash attribution

### Requirement: Global Stop Signal on Crash
The system SHALL halt all workers immediately when crash is detected.

#### Scenario: All workers stop on crash detection
- **WHEN** crash confidence threshold is met
- **THEN** system sends global stop signal to all active workers
- **THEN** all workers cease packet transmission within timeout period
- **THEN** all in-flight requests are allowed to complete or timeout
