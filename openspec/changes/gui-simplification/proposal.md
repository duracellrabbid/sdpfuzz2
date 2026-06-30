## Why

Running SDPFuzz2 currently requires executing multiple separate CLI commands (`discover`, `probe`, and `fuzz`) and parsing terminal tables or JSON logs manually. This creates friction during active vulnerability research. Introducing a unified, modern web interface simplifies target discovery, configuration setup, and live execution monitoring in a single web dashboard.

## What Changes

- Create a decoupled 3-repository architecture consisting of the core `sdpfuzz2` fuzzer library, a `sdpfuzz2-backend` FastAPI layer, and a `sdpfuzz2-frontend` Next.js application.
- Implement one-click target scanning and automatic SDP probing.
- Establish an interactive dashboard displaying real-time metrics (radial status gauges, WebSocket-powered throughput charts, and console logs).

## Capabilities

### New Capabilities
- `gui-backend`: The FastAPI web server acting as a control wrapper over the fuzzer core, providing JSON APIs and WebSocket stats broadcasting.
- `gui-frontend`: The Next.js dashboard providing the visual interface for scan, probe, configuration, and real-time monitoring.

### Modified Capabilities
<!-- No modified capabilities since the core CLI and fuzzing logic are untouched. -->

## Impact

- **Core SDPFuzz2 Library**: None, other than ensuring stable, importable API entrypoints for `DiscoveryService`, `SDPProbe`, and `FuzzRunner`.
- **FastAPI Backend**: New Python repository requiring `fastapi` and `uvicorn`.
- **NextJS Frontend**: New Node.js repository requiring standard web dependencies.
