## ADDED Requirements

### Requirement: Service Discovery and Continuation State Collection
The system SHALL send valid SDP Service Search Attribute requests to the target device and collect all services with their associated continuation states.

#### Scenario: Complete service discovery without continuation
- **WHEN** user initiates SDP probe on selected target
- **THEN** system sends valid Service Search Attribute request to target
- **THEN** system receives complete response without continuation state
- **THEN** system parses response and logs all discovered services

#### Scenario: Service discovery with continuation states
- **WHEN** user initiates SDP probe on target with many services
- **THEN** system sends Service Search Attribute request
- **THEN** system receives response with continuation state indicating more data available
- **THEN** system stores continuation state and sends follow-up request with continuation token
- **THEN** system repeats until no continuation state remains
- **THEN** system aggregates all responses and returns complete service list with all continuation states

#### Scenario: SDP probe timeout
- **WHEN** system sends Service Search Attribute request but target does not respond within timeout
- **THEN** system logs timeout and aborts SDP probe with clear error message

#### Scenario: Malformed or incomplete response
- **WHEN** system receives response with invalid SDP packet format
- **THEN** system logs error details and aborts probe gracefully

### Requirement: Continuation State Storage
The system SHALL store all collected continuation states for use in fuzzing modes.

#### Scenario: Continuation states available for mutation
- **WHEN** SDP probe completes successfully
- **THEN** system stores all discovered continuation states in memory
- **THEN** fuzzing modes can access stored continuation states for mutation operations
