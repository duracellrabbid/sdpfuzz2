## Context

Currently, SDPFuzz2 operates purely as a CLI tool. While CLI execution is robust, it requires multiple sequential commands and manual log tailing to diagnose results. This design establishes a decoupled 3-repository web system to simplify scanning, probing, and real-time session tracking.

## Goals / Non-Goals

**Goals:**
- Decouple GUI components from the core fuzzer code to maintain minimal dependencies in the main CLI.
- Provide a responsive dashboard featuring target status gauges, live line charts for packet rates, and log displays.
- Enforce strict API schemas using Pydantic in the backend to ensure compatibility with frontend changes.

**Non-Goals:**
- Modifying the core Bluetooth L2CAP socket handling or strategy logic.
- Building native GUI wrappers (e.g., PyQt/PySide) that run within display servers on Kali Linux.

## Decisions

### 1. 3-Repository Split
**Decision**: Split the system into `sdpfuzz2` (Core), `sdpfuzz2-backend` (FastAPI), and `sdpfuzz2-frontend` (Next.js).
**Rationale**: Keeps the core codebase clean, light, and focused strictly on the fuzzing domain. Enables frontend and backend code to be maintained and versioned independently.
**Alternatives Considered**:
- Mono-repository: Rejected to prevent web dependencies (FastAPI, npm/Node) from bloating the core Python package.

### 2. NextJS & FastAPI Web Stack
**Decision**: Use Next.js for the frontend and FastAPI + Uvicorn for the backend.
**Rationale**: Next.js allows visual styling with custom vanilla CSS for high-quality dark mode and glassmorphism. FastAPI provides fast asynchronous execution out of the box and seamlessly integrates with the asyncio loop used in `sdpfuzz2`.
**Alternatives Considered**:
- Streamlit: Rejected due to restricted design capabilities, poor WebSocket throughput, and slow UI rendering.

### 3. Pydantic-based API Schema versioning
**Decision**: Validate all REST APIs and WebSocket payloads via Pydantic schemas on the backend.
**Rationale**: Protects both layers from breaking changes if the core CLI logic or log schemas are modified.

## Risks / Trade-offs

- **[Risk]** Interface latency under high packets-per-second fuzzing rate.
  - **Mitigation**: Backend will aggregate live statistic ticks and emit updates to the WebSocket channel at a fixed rate (10Hz) instead of per-packet, preventing frontend thread lock.
- **[Risk]** Version mismatch across repositories during updates.
  - **Mitigation**: Enforce version checking in the backend REST API handshake (`/api/v1/health` or `/api/v1/version`) to warn if dependencies are out of sync.
