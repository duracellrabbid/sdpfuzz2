# SDPFuzz2

SDPFuzz2 is a Python Bluetooth SDP fuzzer that discovers target devices, probes valid SDP state, mutates packets, and records request/response traffic for vulnerability research.

## Development quick start

1. Create and activate a Python 3.11+ environment.
2. Install package and dev dependencies.
3. Run lint, type checks, and tests.

```powershell
pip install -e .[dev]
ruff check .
mypy .
pytest
```

## Current status

Phase 0 scaffolding is in place:
- src-layout package structure
- quality tooling (ruff, mypy, pytest, coverage)
- CI workflow scaffold
- baseline domain and schema tests
