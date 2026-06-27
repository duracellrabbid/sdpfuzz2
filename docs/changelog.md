# Changelog

All notable changes to the SDPFuzz2 project will be documented in this file.

## [0.1.0] - 2026-06-27

Initial MVP Release containing all core Bluetooth and SDP fuzzing modules.

### Added
- **Device Discovery & Interactive Selection**: Added BlueZ D-Bus based discovery listing name, MAC address, and RSSI with interactive selection index.
- **SDP Probe & Continuation Collection**: Added `SDPProbe` query loop paginating target services and saving returned continuation states for fuzzing.
- **Fuzzing Strategies**:
  - `TotallyRandomBytesStrategy` (Totally random byte mutation).
  - `ContinuationStateLengthMutationStrategy` (Oversized continuation-state length fields).
  - `ContinuationStateByteMutationStrategy` (Collected continuation state token mutation).
  - `RandomMutationStrategy` (Flips random bytes inside valid packet templates).
- **Concurrent Worker Pool & Scheduler**: Added bounded async worker pools supporting concurrent fuzzing tasks, queue backpressure, inter-packet delays, and rate limiting.
- **Crash Detection & Confidence Heuristics**: Added crash detection tracking consecutive timeouts, connection state changes (refused/reset), and worker corroboration.
- **Structured JSON Logging**: Implemented incremental flush and atomic file writes conforming to Pydantic schemas.
- **Typer CLI Command Workflow**: Implemented `discover`, `probe`, and `fuzz` subcommands.
- **TDD Quality Infrastructure**: Set up unit/integration/contract test coverage gates, ruff lint checkers, black formatters, and mypy type checks.
