## ADDED Requirements

### Requirement: Multi-Worker Packet Dispatch
The system SHALL dispatch fuzzing packets from multiple concurrent workers to target.

#### Scenario: Multiple workers send packets concurrently
- **WHEN** fuzzing session is active with concurrency > 1
- **THEN** system spawns N worker tasks/threads
- **THEN** each worker independently sends fuzzing packets to target
- **THEN** packets are sent concurrently without blocking

#### Scenario: Bounded worker pool
- **WHEN** user specifies concurrency parameter
- **THEN** system creates exactly N workers (not more, not fewer)
- **THEN** all workers remain active throughout fuzzing session

### Requirement: Request Queue and Backpressure
The system SHALL use bounded queue to prevent memory exhaustion.

#### Scenario: Queue size limits prevent unbounded memory growth
- **WHEN** fuzzing workers generate packets faster than target can receive
- **THEN** system queues packets in bounded queue
- **WHEN** queue reaches maximum size
- **THEN** packet generation pauses (backpressure)
- **THEN** queue drains as workers send packets

#### Scenario: Configurable queue size
- **WHEN** user specifies queue size parameter
- **THEN** system enforces maximum queue size
- **THEN** system prevents unbounded memory allocation

### Requirement: Monotonic Packet Indexing
The system SHALL assign monotonic packet index to each packet for deterministic log correlation.

#### Scenario: Packet index increments for each packet
- **WHEN** fuzzing session generates packet N
- **THEN** system assigns packet index N
- **WHEN** fuzzing session generates next packet
- **THEN** system assigns packet index N+1
- **THEN** indices never repeat or go backwards

#### Scenario: Out-of-order responses correlated to packets
- **WHEN** packets are sent in order 1, 2, 3 but responses arrive in order 3, 1, 2
- **THEN** system uses packet index to map each response to corresponding request
- **THEN** logs show correct pairing despite arrival order

### Requirement: Global Stop Signal
The system SHALL halt all workers gracefully on command.

#### Scenario: Stop signal ceases packet transmission
- **WHEN** global stop signal is triggered (crash detected or user terminates)
- **THEN** all active workers receive stop signal
- **THEN** workers cease generating new packets
- **THEN** workers allow in-flight packets to complete or timeout

#### Scenario: Graceful worker shutdown
- **WHEN** stop signal is sent
- **THEN** workers complete current operations
- **THEN** workers close connections cleanly
- **THEN** system terminates all workers within timeout period

### Requirement: Worker Pool Lifecycle
The system SHALL manage worker startup and shutdown reliably.

#### Scenario: Workers start before first packet
- **WHEN** fuzzing session begins
- **THEN** system starts all workers before generating first packet
- **THEN** workers are ready to send before any packet is queued

#### Scenario: Workers shutdown after fuzzing ends
- **WHEN** fuzzing session terminates (crash or user halt)
- **THEN** system waits for all workers to complete
- **THEN** system closes all worker resources
- **THEN** system confirms all workers shut down before returning
