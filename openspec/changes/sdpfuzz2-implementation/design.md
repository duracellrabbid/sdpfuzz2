## Context

SDPFuzz2 is a modernized rewrite of the original sdpfuzz tool, which targets Bluetooth SDP (Service Discovery Protocol) implementations to identify security vulnerabilities. The original tool was built on L2Fuzz with outdated dependencies. This project applies modern SDLC practices—particularly test-driven development—with clean architecture to enable maintainability and extensibility.

**Development Environment**: Windows PC  
**Runtime Environment**: Kali Linux with external Bluetooth adapter  
**Target Protocol**: Bluetooth SDP (Service Discovery Protocol) over L2CAP  
**Concurrency Model**: Multi-worker packet dispatch with bounded queue and graceful shutdown

## Goals / Non-Goals

**Goals:**
- Build a modern Python-based Bluetooth SDP fuzzer with clean architecture, testability, and near-100% code coverage
- Enable interactive device discovery, target selection, and SDP probing for valid state collection
- Implement four distinct fuzzing strategies with thread/task safety for concurrent execution
- Provide crash detection with confidence scoring to minimize false positives under concurrent failures
- Generate deterministic, analyzable JSON logs with monotonic packet indexing for out-of-order response handling
- Support configurable concurrency (worker pool, queue size, inter-packet delays) for tunable fuzzing throughput
- Deliver comprehensive documentation and runbooks enabling new contributors to set up in <30 minutes

**Non-Goals:**
- GUI support (post-MVP enhancement)
- Response-packet fuzzing (post-MVP enhancement)
- DoS-focused attack workflows (post-MVP enhancement)
- Remote orchestration clusters (future consideration)
- Support for non-Linux runtime environments in MVP

## Decisions

### 1. Python Version and Runtime
**Decision**: Target Python 3.11+ with asyncio for concurrency.  
**Rationale**: Python 3.11 offers improved type hints, performance improvements, and stable async/await semantics. asyncio is part of the standard library, eliminating an external dependency for concurrency orchestration.  
**Alternatives Considered**:
- Python 3.9: Older tooling support; chosen against for improved type system.
- Trio/anyio for concurrency: Deferred to post-MVP; asyncio sufficient for bounded worker pool.

### 2. Bluetooth Transport Layer
**Decision**: Use BlueZ raw L2CAP sockets (via Python `socket` module) for SDP communication, supplemented by `dbus-next` for device discovery and adapter control.  
**Rationale**: Raw sockets provide fine-grained control over malformed payload construction essential for fuzzing. BlueZ D-Bus APIs handle robust device enumeration, adapter state, and power management without reimplementing system integration. This approach aligns with Kali's default Bluetooth stack.  
**Alternatives Considered**:
- `pybluez`: Higher abstraction; less control for malformed packets.
- `scapy`: Good for packet inspection; not ideal as the primary transport layer for high-rate concurrent SDP fuzzing.
- Direct HCI sockets: Lower-level but more brittle; BlueZ abstraction acceptable for MVP.

### 3. Packet Building and Parsing
**Decision**: Implement custom SDP packet builder and parser using byte-level construction and explicit state machines.  
**Rationale**: SDP is a simple binary protocol; custom implementation avoids heavyweight dependencies and gives full control over malformation. Facilitates precise mutation strategies (e.g., length fuzzing, random-byte mutation on continuation states).  
**Alternatives Considered**:
- Pre-built Bluetooth libraries (e.g., `bluepy`): Abstracts packet details; unsuitable for generating intentionally malformed packets.
- Scapy layers: Over-engineered for a single-protocol MVP.

### 4. Data Validation and Logging
**Decision**: Use Pydantic for runtime log schema validation and JSON serialization.  
**Rationale**: Pydantic provides type safety, automatic JSON encoding, and schema versioning support. Ensures log integrity and facilitates future schema evolution.  
**Alternatives Considered**:
- Plain dataclasses + jsonschema: More boilerplate; less IDE autocomplete.
- No schema validation: Risk of malformed logs corrupting analysis.

### 5. CLI and User Interaction
**Decision**: Use Typer for CLI definition and Rich for terminal UI (progress bars, formatted output).  
**Rationale**: Typer automates argument parsing and help generation. Rich provides polished terminal output for device lists and progress feedback.  
**Alternatives Considered**:
- argparse: Verbose; requires manual formatting.
- Click: More mature but more verbose than Typer.

### 6. Testing and Coverage Strategy
**Decision**: TDD-first approach with pytest, hypothesis for property tests, and pytest-cov with enforced coverage gates.  
**Rationale**: Enables early bug detection, facilitates refactoring confidence, and keeps mutation logic verifiable. Hypothesis finds edge cases in fuzz strategy randomness. Coverage gates prevent untested code paths in critical modules.  
**Alternatives Considered**:
- unittest (standard library): Less ergonomic than pytest; no property test framework.
- Manual testing: Insufficient for concurrency and edge-case validation.

### 7. Crash Detection Strategy
**Decision**: Multi-level confidence scoring based on timeout frequency, connection state transitions, and corroboration across workers.  
**Rationale**: True remote crash attribution is hard; confidence levels reduce false positives from transient packet loss. Requires either corroboration across workers or a failed control probe after worker failures.  
**Alternatives Considered**:
- Single timeout = crash: Too noisy; false positives from packet loss.
- Strict connection logging: Insufficient without control probes.

### 8. Concurrency Model
**Decision**: Bounded worker pool (asyncio tasks) with configurable concurrency, shared request queue, monotonic packet indexing, and global stop signal.  
**Rationale**: Backpressure via bounded queue prevents unbounded memory growth. Monotonic packet indexing ensures logs remain analyzable even when responses arrive out of order. Global stop signal halts all workers immediately on crash detection.  
**Alternatives Considered**:
- Thread pool: Overkill for I/O-bound network tasks.
- Unbounded queue: Risk of memory exhaustion during high-rate fuzzing.
- No packet indexing: Difficult to correlate responses to requests.

### 9. Logging and Artifact Format
**Decision**: Structured JSON logs with incremental periodic flush and crash-safe writes.  
**Rationale**: JSON enables downstream parsing and analysis. Incremental flush reduces memory footprint and enables recovery from partial runs. Crash-safe writes (atomic file operations) ensure data integrity.  
**Alternatives Considered**:
- CSV: Less flexible for nested data (e.g., response timing, worker metadata).
- Plain text: Hard to parse programmatically.

### 10. Project Structure and Package Layout
**Decision**: Src-layout with `src/sdpfuzz2/` containing submodules: `bluetooth/`, `sdp/`, `fuzzing/`, `logging/`, `orchestration/`, `domain/`.  
**Rationale**: Src-layout prevents namespace pollution and simplifies packaging. Logical grouping by function aids navigation and dependency management.  
**Alternatives Considered**:
- Flat layout: Higher risk of circular imports.
- Monorepo: Unnecessary for a single-purpose tool.

## Risks / Trade-offs

| Risk | Mitigation |
|------|-----------|
| **BlueZ socket API instability on newer kernels** | Test on Kali's current kernel; provide fallback D-Bus transport if needed. Document kernel compatibility. |
| **Packet loss causing false crash positives** | Implement confidence scoring; require corroboration across workers or control probe failures. |
| **Concurrency race conditions in worker shutdown** | Use asyncio cancellation patterns and unit tests with deterministic fakes; avoid shared mutable state. |
| **High memory growth under sustained high-rate fuzzing** | Bounded queue backpressure; configurable worker count and queue size. Monitor in integration tests. |
| **SDP protocol evolution or vendor-specific deviations** | Modular packet builder design allows targeted fixes; templating system supports vendor variants post-MVP. |
| **Development on Windows, runtime on Linux** | Abstract Bluetooth I/O behind interface; unit tests run on Windows; integration tests gated to Linux. |
| **100% coverage target delaying MVP release** | Start at 90% coverage; raise incrementally. Document justification for any uncovered paths (e.g., hardware-only error paths). |

## Migration Plan

**Phased Delivery**:
1. **Phase 0 (Week 1)**: Project bootstrap, lint/test infrastructure, domain model tests.
2. **Phase 1 (Week 1)**: Discovery and selection with CLI.
3. **Phase 2 (Week 2)**: SDP probe and continuation-state collection.
4. **Phase 3 (Week 3)**: All four fuzzing strategies with contract and property tests.
5. **Phase 4 (Week 4)**: Runner, crash detection, worker scheduler, JSON logging.
6. **Phase 5 (Week 5)**: E2E integration, CLI hardening, documentation.

**Deployment**: CI artifacts (pytest results, coverage reports) on every push. Integration tests gated to Linux runners. Manual Kali testing before release.

## Open Questions

1. **Exact crash detection threshold**: How many consecutive timeouts or connection failures constitute "high confidence crash"? (Recommend: 3-5 configurable.)
2. **Maximum fuzzing duration**: Should MVP support time-based termination, or only crash-triggered? (Recommend: Add in Phase 5 as CLI flag.)
3. **Vendor-specific SDP variants**: Will MVP target generic SDP, or specific implementations (e.g., Apple, Samsung)? (Recommend: Generic SDP for MVP; vendor templates post-MVP.)
4. **Crash log preservation**: Should partial crashes (e.g., one worker crash) stop all workers, or only when N workers crash? (Recommend: Configurable threshold; default to 1 for safety.)
5. **Response timeout calibration**: How to set per-target timeout thresholds? Automatic learning, or manual config? (Recommend: Manual config in MVP; adaptive learning post-MVP.)
