# Architecture Documentation

This document describes the architectural layout, modules, and component responsibilities of SDPFuzz2.

## 1. System Overview

SDPFuzz2 follows a clean, decoupled architecture. High-level network transport, packet building, orchestration scheduling, and logging are kept distinct to facilitate testing, cross-platform compilation, and future extension.

```
                    +------------------------------------+
                    |                CLI                 |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    |             FuzzRunner             |
                    +------------------------------------+
                       /              |               \
                      v               v                v
            +------------+    +---------------+    +------------+
            |  Strategy  |    |   Scheduler   |    | RunLogger  |
            +------------+    +---------------+    +------------+
                  |                   |                  |
                  v                   v                  v
            +------------+    +---------------+    +------------+
            | PacketBuilder   |  Worker Pool  |    |   Schema   |
            +------------+    +---------------+    +------------+
                                      |
                                      v
                              +---------------+
                              |   Transport   |
                              +---------------+
```

---

## 2. Module Responsibilities

### 2.1 `sdpfuzz2.domain`
- **Purpose**: Defines pure domain entities and common error structures. Contains no network or protocol details.
- **Key Files**:
  - `models.py`: Core dataclasses like `Device` (discovered target) and `PacketLogEntry` / `RunLog` definitions.
  - `errors.py`: Custom error hierarchy including `TransportError` and `PacketParseError`.

### 2.2 `sdpfuzz2.bluetooth`
- **Purpose**: Low-level Bluetooth system discovery and network socket transport.
- **Key Files**:
  - `discovery.py`: Orchestrates discovery scans. Abstracts BlueZ D-Bus discovery interface on Linux, falling back to a `NoopDiscoveryBackend` on non-Linux platforms for test runnability.
  - `l2cap_transport.py`: Concrete `Transport` implementation using raw Linux/BlueZ L2CAP sockets over the SDP PSM (`0x0001`).
  - `probe.py`: Stateful probe orchestrator (`SDPProbe`) running the pagination loop to retrieve all target attributes and continuation states.
  - `crash_detector.py`: Crash analysis logic (`CrashDetector`) containing heuristics for consecutive timeouts, connection refusals, and corroboration scoring.

### 2.3 `sdpfuzz2.sdp`
- **Purpose**: Binary serialization, deserialization, templates, and mutation helper functions for the SDP protocol.
- **Key Files**:
  - `packet_builder.py`: Packs SDP requests (Service Search Attribute Request) into raw bytes.
  - `parser.py`: Unpacks raw responses and extracts payload attributes and continuation states.
  - `templates.py`: Contains valid SDP request template byte sequences used for template mutations.
  - `continuation.py`: Mutator helpers for modifying continuation token bytes.

### 2.4 `sdpfuzz2.fuzzing`
- **Purpose**: Implementation of all fuzzing strategies adhering to the common `FuzzingStrategy` contract.
- **Key Files**:
  - `base.py`: Defines the `FuzzingStrategy` abstract base class interface.
  - `random_bytes.py`: Generates totally random byte packets constrained within size bounds.
  - `cont_state_len_mutation.py`: Emits requests containing oversized continuation state length fields.
  - `cont_state_byte_mutation.py`: Randomly mutates continuation state bytes while preserving valid lengths.
  - `random_mutation.py`: Selects template packets and flips random byte positions.

### 2.5 `sdpfuzz2.orchestration`
- **Purpose**: Handles scheduler queues, concurrency limits, and running fuzzer loop coordination.
- **Key Files**:
  - `runner.py`: Orchestrates the fuzzing session lifecycle, loops strategies, schedules requests, logs exchanges, and handles termination on crash discovery.
  - `scheduler.py`: Thread-safe monotonic task indexing and queue scheduling.
  - `workers.py`: Concurrent workers (`FuzzWorker`) that perform synchronous I/O socket calls inside executor threads with delay / rate limits.

### 2.6 `sdpfuzz2.logging`
- **Purpose**: Structured logging format definitions and crash-safe file serialization.
- **Key Files**:
  - `schema.py`: Pydantic model schemas enforcing strict verification of log files.
  - `run_logger.py`: Thread-safe, atomic log writer writing output files incrementally to protect data in the event of forced program termination.
