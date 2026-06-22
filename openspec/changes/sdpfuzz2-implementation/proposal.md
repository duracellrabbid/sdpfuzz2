## Why

The existing sdpfuzz project is built on L2Fuzz with unmaintained dependencies, making it difficult to maintain and extend. SDPFuzz2 is a modernized refresh that uses current dependencies, modern SDLC practices (test-driven development), and clean architecture to enable security researchers to fuzz Bluetooth SDP implementations and discover vulnerabilities.

## What Changes

- **New fuzzer tool**: Python-based Bluetooth SDP fuzzer that runs on Kali Linux with external Bluetooth adapter.
- **Device discovery**: Interactive device discovery listing devices with names and MAC addresses.
- **SDP probing**: Sends valid Service Search Attribute requests to gather services and continuation states before fuzzing.
- **Multiple fuzzing modes**: Four fuzz strategies (random bytes, continuation state length mutation, continuation state random-byte mutation, random mutation on templates).
- **Crash detection**: Automatic detection and termination when target crashes (via timeouts, connection failures, or HCI errors).
- **JSON logging**: All requests/responses logged in structured JSON format with packet indexing for out-of-order response handling.
- **Concurrent fuzzing**: Bounded worker pool for concurrent packet sending to increase fuzzing throughput.

## Capabilities

### New Capabilities
- `device-discovery`: Scan for Bluetooth devices and present list with names and MAC addresses for user selection.
- `sdp-probe`: Send valid Service Search Attribute requests to collect all services and continuation states from target.
- `fuzz-random-bytes`: Generate and send completely random Bluetooth SDP packets (16-N bytes configurable).
- `fuzz-continuation-length`: Mutate continuation state length to arbitrary large values while keeping other SDP fields valid.
- `fuzz-continuation-bytes`: Randomly mutate continuation state bytes while preserving valid length from collected states.
- `fuzz-random-mutation`: Generate valid SDP requests and randomly mutate bytes to introduce fuzz.
- `crash-detection`: Detect target crashes via timeout thresholds, connection failures, HCI errors, and confidence scoring.
- `concurrent-fuzzing`: Run multiple fuzzing workers in parallel with bounded queue and graceful shutdown.
- `json-logging`: Write all packets and responses to structured JSON logs with deterministic packet indexing.
- `cli-interface`: Command-line interface for device selection, mode selection, parameter configuration, and output management.

### Modified Capabilities
<!-- None - this is a new project -->

## Impact

- **New module**: `sdpfuzz2` package with submodules for Bluetooth, SDP, fuzzing, logging, and orchestration.
- **New dependencies**: pytest, pydantic, typer, rich, structlog, dbus-next, anyio for core functionality and testing.
- **Development platform**: Windows (dev), Kali Linux (runtime).
- **Python version**: 3.11+
- **Testing**: Test-driven development with pytest, hypothesis for property tests, pytest-cov for coverage tracking targeting 100%.
- **CI/CD**: Automated CI on every push for unit tests (Windows/Linux) and integration tests (Linux only).
