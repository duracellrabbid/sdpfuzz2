## ADDED Requirements

### Requirement: SQLite Database Indexing
The system SHALL maintain a SQLite index database (`corpus.db`) to catalog all saved packet sequences.

#### Scenario: Index database initialization
- **WHEN** the corpus manager is initialized
- **THEN** the system SHALL create `corpus.db` and the `sequences` table if they do not exist

#### Scenario: Registering a sequence in the index
- **WHEN** a new packet sequence is saved
- **THEN** the system SHALL insert a record in the `sequences` table with unique ID, classification, target MAC, timestamp, packet count, file path, and metadata

### Requirement: Length-Prefixed Binary Sequence Storage
The system SHALL store raw request packet sequences in individual binary `.bin` files using length-prefixed encoding.

#### Scenario: Saving sequence payload to binary file
- **WHEN** a sequence of N packets is saved
- **THEN** the system SHALL write a `.bin` file containing the 2-byte packet count, followed by each packet's 2-byte payload length and raw payload bytes

### Requirement: Sliding Window Packet History
The system SHALL keep a sliding window history of the last `N` sent packets across all workers during active fuzzing.

#### Scenario: Logging packet history to circular queue
- **WHEN** a worker sends a packet
- **THEN** the system SHALL record the packet index and payload in a circular queue of max size `N` defined by CLI parameter

### Requirement: Automatic Recording on Failure
The system SHALL automatically save the sliding window packet history to the corpus when a crash or timeout is detected.

#### Scenario: Auto-save on crash detection
- **WHEN** a crash event is detected by the FuzzRunner
- **THEN** the system SHALL write the last `N` packets to a binary file and register it in `corpus.db` with `classification` set to `crash_candidate`

#### Scenario: Auto-save on timeout detection
- **WHEN** a worker timeout error is recorded
- **THEN** the system SHALL write the last `N` packets to a binary file and register it in `corpus.db` with `classification` set to `timeout_candidate`

### Requirement: Deterministic Replay (Workflow A)
The system SHALL allow deterministic replay of saved packet sequences from the corpus.

#### Scenario: Replaying a sequence successfully
- **WHEN** the user selects a saved sequence for replay
- **THEN** the system SHALL establish transport, read raw packets from the corresponding `.bin` file, send them sequentially, and report whether a crash or timeout occurred

#### Scenario: Replay loop execution
- **WHEN** replay is launched with a loop/iteration count parameter
- **THEN** the system SHALL repeat the sequence execution up to the specified limit or until a crash is detected

#### Scenario: Replay failure fallback to mutation
- **WHEN** replay finishes with no crash detected and mutate fallback flag is enabled
- **THEN** the system SHALL transition automatically to corpus-mutation fuzzing using the replayed sequence as the seed

### Requirement: Replay Target Device Selection
The system SHALL support selecting the target device for replay and MUST NOT assume the original MAC address.

#### Scenario: Replay with explicit target
- **WHEN** replay is launched with a target MAC address specified via CLI argument
- **THEN** the system SHALL use the specified target MAC address instead of the metadata target MAC address

#### Scenario: Replay with interactive target selection
- **WHEN** replay is launched in interactive mode and no target MAC address is specified
- **THEN** the system SHALL run the target device discovery and selection workflow to establish the replay target


### Requirement: Corpus-Mutation Fuzzing (Workflow B)
The system SHALL allow fuzzing using mutated packets seeded from saved corpus sequences.

#### Scenario: Fuzzing with mutated seeds
- **WHEN** corpus-mutation strategy is active
- **THEN** the system SHALL pick a random sequence from `corpus.db`, load its packets from the `.bin` file, apply mutations to a selected packet, and return it as the next fuzzing payload

### Requirement: Corpus Synchronization and Clean
The system SHALL provide a cleanup command to synchronize the database index and the binary files on disk.

#### Scenario: Cleanup database records and orphan files
- **WHEN** `sdpfuzz2 clean` is executed
- **THEN** the system SHALL remove database records with missing `.bin` files and delete `.bin` files that do not have a corresponding record in the database
