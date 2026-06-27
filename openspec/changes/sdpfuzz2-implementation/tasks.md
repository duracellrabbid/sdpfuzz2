## 1. Project Bootstrap and Tooling

- [x] 1.1 Initialize git repository and pyproject.toml with src-layout structure
- [x] 1.2 Configure Python 3.11+ version requirement and core dependencies (pytest, pydantic, typer, rich, structlog, dbus-next, anyio)
- [x] 1.3 Set up ruff/black for linting and formatting
- [x] 1.4 Configure mypy with strict type checking
- [x] 1.5 Set up pytest with pytest-cov for coverage tracking (start at 90% gate)
- [x] 1.6 Create test structure (unit/, integration/, contract/ directories)
- [x] 1.7 Configure CI pipeline to run tests on every push (Windows/Linux for units, Linux-only for integration)
- [x] 1.8 Write initial failing tests for domain models (Device, Service, ContinuationState)
- [x] 1.9 Create log schema models with Pydantic (LogEntry, FuzzingSession, RequestResponseLog)
- [x] 1.10 Verify CI green with baseline tests at 90% coverage

## 2. Device Discovery and Selection

- [x] 2.1 Write unit tests for BlueZ device discovery adapter (mock backend)
- [x] 2.2 Implement discovery service interface abstracting Bluetooth I/O
- [x] 2.3 Implement BlueZ D-Bus adapter for device enumeration on Linux
- [x] 2.4 Implement device filtering and normalization (name, MAC, signal strength)
- [x] 2.5 Write tests for interactive device selection CLI
- [x] 2.6 Implement target selector with index-based input validation
- [x] 2.7 Create Typer CLI command for `sdpfuzz2 discover`
- [x] 2.8 Add Rich terminal UI for device list display (formatted table)
- [x] 2.9 Write integration tests for discovery on mock SDP server
- [x] 2.10 Verify phase complete: can list devices and select target without real hardware

## 3. SDP Probe and Continuation State Collection

- [x] 3.1 Write unit tests for SDP packet builder against known byte fixtures
- [x] 3.2 Implement SDP packet builder for Service Search Attribute request
- [x] 3.3 Write unit tests for SDP response parser (complete, continuation, malformed)
- [x] 3.4 Implement SDP response parser with continuation state extraction
- [x] 3.5 Write contract tests for probe behavior (timeout, retry, state collection)
- [x] 3.6 Implement SDPProbe class with configurable timeout and retry logic
- [x] 3.7 Implement continuation state collection loop (iterative requests until no more data)
- [x] 3.8 Write integration tests for probe with mock SDP server
- [x] 3.9 Add CLI command `sdpfuzz2 probe --target <MAC>` for manual probing
- [x] 3.10 Verify phase complete: probe collects all services and continuation states from mock server

## 4. Fuzzing Strategies

- [x] 4.1 Write shared strategy contract tests (output bytes, deterministic with seed, thread-safe)
- [x] 4.2 Implement RandomBytesFuzzer (16..N byte generation, seeded RNG)
- [x] 4.3 Write property tests for random bytes strategy with Hypothesis
- [x] 4.4 Implement ContinuationLengthMutator (oversized length field)
- [x] 4.5 Write property tests for continuation length mutation
- [x] 4.6 Implement ContinuationBytesMutator (random bytes in continuation state, preserve length)
- [x] 4.7 Write property tests for continuation bytes mutation
- [x] 4.8 Implement RandomMutationFuzzer (valid template + random byte flips)
- [x] 4.9 Write property tests for random mutation strategy
- [x] 4.10 Verify all strategies pass contract and property tests
- [x] 4.11 Verify all strategies are thread/task-safe under concurrent access
- [x] 4.12 Verify strategies support deterministic seeding for reproducible fuzzing

## 5. Crash Detection and Confidence Scoring

- [x] 5.1 Write unit tests for CrashDetector with simulated crash scenarios
- [x] 5.2 Implement timeout-based crash detection (N consecutive timeouts)
- [x] 5.3 Implement connection-state crash detection (refused/reset after success)
- [x] 5.4 Implement HCI error classification (local vs remote)
- [x] 5.5 Write tests for crash confidence scoring (high/medium/unknown)
- [x] 5.6 Implement worker corroboration logic (multi-worker agreement increases confidence)
- [x] 5.7 Implement control probe validation (send known-good packet to validate crash)
- [x] 5.8 Write tests for false-positive mitigation under packet loss
- [x] 5.9 Implement global stop signal broadcast to all workers
- [x] 5.10 Verify crash detection meets confidence requirements without false positives

## 6. Concurrent Worker Pool and Scheduling

- [x] 6.1 Write tests for worker lifecycle (start, send, receive, stop)
- [x] 6.2 Implement Worker async task class with packet send/receive loop
- [x] 6.3 Implement WorkerPool with configurable concurrency (N workers)
- [x] 6.4 Implement bounded request queue with configurable size
- [x] 6.5 Implement monotonic packet indexing for deterministic log correlation
- [x] 6.6 Implement response mapping from packets to requests using packet_index
- [x] 6.7 Write tests for out-of-order response handling
- [x] 6.8 Implement inter-packet delay and rate limiting
- [x] 6.9 Implement graceful worker shutdown with timeout
- [x] 6.10 Write concurrency tests with deterministic fakes (no race conditions)
- [x] 6.11 Verify workers safely run in parallel without memory safety issues

## 7. Runner Loop and Orchestration

- [x] 7.1 Write tests for FuzzRunner with fake transport and crash detector
- [x] 7.2 Implement FuzzRunner main loop (worker coordination, crash checks, stop signal)
- [x] 7.3 Implement session management (start, run, pause, stop, resume)
- [x] 7.4 Implement statistics tracking (packets sent, received, timeouts, crashes)
- [x] 7.5 Implement exception handling and recovery from transient failures
- [x] 7.6 Write tests for runner lifecycle (setup, running, termination)
- [x] 7.7 Implement signal handling for user interruption (Ctrl+C)
- [x] 7.8 Write integration tests for runner with mock transport and crash detector
- [x] 7.9 Verify runner correctly orchestrates all components

## 8. JSON Logging and Artifact Writing

- [x] 8.1 Write unit tests for RunLogger with Pydantic schema validation
- [x] 8.2 Implement RunLogger with incremental log entry writing
- [x] 8.3 Implement JSON serialization with hex-encoded packet bytes
- [x] 8.4 Implement periodic flush (configurable interval)
- [x] 8.5 Implement atomic file writes (temporary file + rename)
- [x] 8.6 Implement crash-safe log recovery after unexpected termination
- [x] 8.7 Add optional metadata fields (fuzz_mode, worker_id, run_id, in_flight_at_send)
- [x] 8.8 Write tests for log schema validation
- [x] 8.9 Write tests for out-of-order entry logging with packet_index correlation
- [x] 8.10 Verify logs remain valid even after crash or forced termination

## 9. CLI Interface and User Workflows

- [x] 9.1 Implement `sdpfuzz2 discover` command with device list and selection
- [x] 9.2 Implement `sdpfuzz2 fuzz` command with mode selection (interactive or via --mode)
- [x] 9.3 Add CLI parameters: --mode, --target, --concurrency, --queue-size, --max-length, --delay, --rate-limit, --seed, --output, --verbose
- [x] 9.4 Add parameter validation and helpful error messages
- [x] 9.5 Implement progress display during fuzzing (packets sent, responses, elapsed time)
- [x] 9.6 Add real-time crash status display
- [x] 9.7 Implement help system (--help, command-specific help)
- [x] 9.8 Add log output configuration (path, default naming with timestamp + MAC)
- [x] 9.9 Write integration tests for complete CLI workflows
- [x] 9.10 Verify all CLI commands work end-to-end

## 10. Integration Testing and E2E Validation

- [x] 10.1 Build minimal mock SDP server for repeatable integration tests
- [x] 10.2 Write integration tests for complete discovery → probe → fuzz → crash workflow
- [x] 10.3 Write integration tests for all four fuzzing modes
- [x] 10.4 Write integration tests for crash detection with simulated crash behavior
- [x] 10.5 Write integration tests for concurrent fuzzing with multiple workers
- [x] 10.6 Write integration tests for JSON log output and schema validation
- [ ] 10.7 Test on Kali Linux with real Bluetooth adapter (manual gated)
- [ ] 10.8 Verify end-to-end reproducibility with seed-based runs

## 11. Documentation and Operational Hardening

- [x] 11.1 Write README with project overview, dependencies, and quick start
- [ ] 11.2 Write Kali setup runbook (permissions, adapter setup, BlueZ configuration)
- [ ] 11.3 Write troubleshooting guide (adapter issues, timeout tuning, crash detection calibration)
- [ ] 11.4 Document SDP protocol specifics and packet format for maintainability
- [ ] 11.5 Write architecture documentation with module responsibilities
- [ ] 11.6 Create contributing guide for new developers
- [ ] 11.7 Add code examples for extending fuzzing strategies post-MVP
- [ ] 11.8 Document log schema and how to analyze logs
- [ ] 11.9 Verify documentation enables new contributor setup in <30 minutes
- [ ] 11.10 Create changelog and version tags for release

## 12. Coverage and Quality Assurance

- [ ] 12.1 Review coverage report and target 90%+ coverage across all modules
- [ ] 12.2 Identify and justify any intentionally uncovered code (hardware-only paths)
- [x] 12.3 Enforce coverage gate in CI pipeline
- [ ] 12.4 Run full test suite (unit, integration, property) and verify all pass
- [ ] 12.5 Run linting (ruff) and formatting (black) with zero warnings
- [ ] 12.6 Run type checking (mypy) with strict mode and zero errors
- [ ] 12.7 Perform manual security review of Bluetooth socket handling
- [ ] 12.8 Test CLI edge cases (invalid inputs, missing parameters, interruption)
- [ ] 12.9 Verify project meets all MVP requirements
- [ ] 12.10 Prepare release artifacts and final documentation

## 13. Post-MVP Roadmap (Future)

- [ ] 13.1 Add response-packet fuzzing capabilities
- [ ] 13.2 Design and implement GUI for workflow simplification
- [ ] 13.3 Add corpus management (save interesting packets, replay mode)
- [ ] 13.4 Implement seed management and deterministic run manifests
- [ ] 13.5 Add mutation coverage metrics
- [ ] 13.6 Create containerized Kali dev/test image
- [ ] 13.7 Add PCAP or btsnoop export for protocol analysis
- [ ] 13.8 Add pluggable protocol architecture for other Bluetooth profiles
- [ ] 13.9 Implement adaptive timeout learning for targets
- [ ] 13.10 Add DoS-focused SDP stress modules (with strict safety controls)
