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

## Running the project

Install the package in editable mode if you have not already done so:

```powershell
pip install -e .[dev]
```

Run the CLI:

```powershell
sdpfuzz2 version
sdpfuzz2 scaffold-status
sdpfuzz2 discover
```

The discovery command lists named Bluetooth devices with their MAC addresses and then prompts you to select a target. You can also pass an explicit index:

```powershell
sdpfuzz2 discover --index 1
```

Run the test suite:

```powershell
pytest
```

Run unit checks with coverage and exclude integration tests:

```powershell
pytest -m "not integration" --cov=src/sdpfuzz2 --cov-report=term-missing --cov-fail-under=90
```

Run integration tests without coverage enforcement:

```powershell
pytest -m integration --no-cov
```

## BlueZ and dbus-next notes

The Bluetooth discovery backend uses BlueZ over `dbus-next` on Linux. The current implementation is designed for Kali Linux or another BlueZ-based distribution with an external Bluetooth adapter.

Runtime notes:
- `dbus-next` is installed automatically when you install the package on Linux.
- BlueZ must be installed and running on the target Linux machine.
- The Bluetooth adapter should be visible to BlueZ and able to scan devices.
- Discovery uses the system D-Bus, so run the project in an environment with access to the system bus.
- On non-Linux platforms, discovery falls back to a no-op backend so unit tests and development remain runnable on Windows.

## Dependency scanning workflow

Install pre-commit hooks:

```powershell
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Run dependency scan manually:

```powershell
python scripts/check_dependency_vulns.py
```

Behavior:
- A dependency vulnerability scan runs on both commit and push.
- Commits/pushes are blocked on medium/high/critical findings.
- Findings without severity metadata are not blocking.

## Current status

Phase 1 discovery and selection are in place:
- Linux BlueZ discovery backend using dbus-next
- Discovery normalization and filtering
- CLI target selection flow
- Unit tests for discovery and selection

Earlier scaffolding is also in place:
- src-layout package structure
- quality tooling (ruff, mypy, pytest, coverage)
- CI workflow scaffold
- baseline domain and schema tests
