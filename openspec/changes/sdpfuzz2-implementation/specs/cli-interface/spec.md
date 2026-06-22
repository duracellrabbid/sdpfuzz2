## ADDED Requirements

### Requirement: Device Discovery Command
The system SHALL provide CLI command to initiate device discovery.

#### Scenario: Discover and list Bluetooth devices
- **WHEN** user runs `sdpfuzz2 discover` command
- **THEN** system scans for nearby Bluetooth devices
- **THEN** system displays numbered list of devices with names and MAC addresses
- **THEN** system prompts user to select target device by index

#### Scenario: Device list formatted for easy reading
- **WHEN** device discovery completes
- **THEN** system displays devices in table format with index, name, and MAC address columns
- **THEN** system indicates if any devices are currently connected

### Requirement: Mode Selection
The system SHALL allow user to select fuzzing mode via CLI.

#### Scenario: Select fuzzing mode interactively
- **WHEN** user runs fuzzing command without mode parameter
- **THEN** system displays menu of available fuzzing modes
- **THEN** modes shown: random-bytes, continuation-length, continuation-bytes, random-mutation
- **WHEN** user selects mode
- **THEN** system proceeds with mode-specific configuration

#### Scenario: Specify mode via CLI parameter
- **WHEN** user runs `sdpfuzz2 fuzz --mode random-bytes --target <MAC>`
- **THEN** system skips mode selection menu
- **THEN** system uses specified mode

### Requirement: Parameter Configuration
The system SHALL accept and validate configuration parameters.

#### Scenario: Random bytes mode parameters
- **WHEN** user selects random-bytes mode
- **THEN** user can specify `--max-length N` for maximum packet length
- **THEN** default max-length provided if not specified

#### Scenario: Concurrency parameters
- **WHEN** user starts fuzzing
- **THEN** user can specify `--concurrency N` for number of workers
- **THEN** user can specify `--queue-size N` for maximum queue size
- **THEN** reasonable defaults provided if not specified

#### Scenario: Packet rate limiting
- **WHEN** user wants to control fuzzing rate
- **THEN** user can specify `--delay MS` for inter-packet delay
- **THEN** user can specify `--rate-limit PPS` for packets per second limit
- **THEN** system enforces specified rate limit

#### Scenario: Reproducibility parameters
- **WHEN** user wants reproducible fuzzing session
- **THEN** user can specify `--seed N` for random seed
- **THEN** same seed produces identical packet sequence on subsequent runs

### Requirement: Output Configuration
The system SHALL allow user to specify output log location.

#### Scenario: Specify output path
- **WHEN** user runs fuzzing command
- **THEN** user can specify `--output <path>` for log file location
- **THEN** system writes JSON log to specified path
- **THEN** default output path provided if not specified

#### Scenario: Default output naming
- **WHEN** output path not specified
- **THEN** system generates filename with timestamp and target MAC
- **THEN** file stored in configurable default output directory

### Requirement: Session Control
The system SHALL provide commands to control fuzzing session.

#### Scenario: Start fuzzing session
- **WHEN** user runs `sdpfuzz2 fuzz` command with all required parameters
- **THEN** system performs SDP probe on target
- **THEN** system collects continuation states
- **THEN** system starts fuzzing workers
- **THEN** system displays progress feedback

#### Scenario: Monitor session progress
- **WHEN** fuzzing session is active
- **THEN** system displays real-time progress (packets sent, responses received, elapsed time)
- **THEN** system displays current crash status

#### Scenario: User terminates session
- **WHEN** user presses Ctrl+C during fuzzing
- **THEN** system stops fuzzing gracefully
- **THEN** system flushes logs
- **THEN** system exits cleanly

#### Scenario: Auto-terminate on crash
- **WHEN** crash is detected during fuzzing
- **THEN** system halts all workers
- **THEN** system displays crash information
- **THEN** system flushes final logs
- **THEN** system exits with appropriate status code

### Requirement: Help and Documentation
The system SHALL provide CLI help information.

#### Scenario: Display help information
- **WHEN** user runs `sdpfuzz2 --help`
- **THEN** system displays all available commands
- **THEN** system displays all available parameters with descriptions
- **WHEN** user runs `sdpfuzz2 discover --help`
- **THEN** system displays help specific to discover command

#### Scenario: Verbose logging option
- **WHEN** user specifies `--verbose` or `-v` flag
- **THEN** system displays detailed diagnostic information during execution
- **THEN** system logs debug information to console
