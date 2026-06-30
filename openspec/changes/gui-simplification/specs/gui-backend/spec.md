## ADDED Requirements

### Requirement: Device Discovery API Endpoint
The backend API SHALL expose an HTTP GET endpoint `/api/v1/discover` that invokes the core `DiscoveryService`.

#### Scenario: Successful device scan
- **WHEN** a client performs a GET request on `/api/v1/discover`
- **THEN** the backend returns a list of discovered named devices containing MAC address and device name with a `200 OK` status.

### Requirement: Target Probing API Endpoint
The backend API SHALL expose an HTTP POST endpoint `/api/v1/probe` that accepts a target MAC address and triggers the `SDPProbe` routine.

#### Scenario: Successful SDP target probe
- **WHEN** a client performs a POST request on `/api/v1/probe` with a valid JSON body containing a device MAC address
- **THEN** the backend returns the collected attribute fragments, continuation states, and combined attribute payload size.

### Requirement: WebSocket Fuzzing Stream Control
The backend API SHALL expose a WebSocket endpoint `/api/v1/fuzz/ws` to manage fuzz session state and stream live run statistics.

#### Scenario: Start fuzzing session and stream stats
- **WHEN** a client establishes a WebSocket connection and transmits a JSON payload containing the target MAC address, concurrency, strategy mode, and run limits
- **THEN** the backend spins up the `FuzzRunner`, streams periodic JSON stats objects and request/response packet log frames over WebSocket, and halts execution when a stop command is received.
