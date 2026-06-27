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
sdpfuzz2 probe --index 1
```

The discovery command lists named Bluetooth devices with their MAC addresses and then prompts you to select a target. You can also pass an explicit index:

```powershell
sdpfuzz2 discover --index 1
```

Probe the selected target to collect valid SDP response pages and continuation states:

```powershell
sdpfuzz2 probe --index 1 --response-timeout-ms 1500
```

Include debug output to print page-by-page and continuation-state hex values:

```powershell
sdpfuzz2 probe --index 1 --debug
```

The CLI `probe` command is integrated with `SDPProbe` and uses the Linux L2CAP transport implementation to connect to the selected target MAC over SDP PSM (`0x0001`).
When `--debug` is enabled, the CLI prints additional probe details including each attribute page payload hex, continuation state hex values, and the combined payload hex.

Run the test suite:

```powershell
pytest
```

Run unit checks with coverage and exclude integration tests:

```powershell
pytest -m "not integration" --cov=src/sdpfuzz2 --cov-report=term-missing --cov-fail-under=100
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

## Developer notes

### SDP Probing Flow

The probe flow sends a valid Service Search Attribute request, parses the response, and continues probing while the remote server returns non-empty continuation states.

Programmatic example:

```python
from sdpfuzz2.bluetooth.probe import SDPProbe

# transport must implement send(payload: bytes) and receive(timeout_ms: int) -> bytes
probe = SDPProbe(transport=my_transport, response_timeout_ms=1500)
result = probe.collect_initial_state()

print(result.continuation_states)
print(result.full_attribute_list.hex())
```

### Concurrent Scheduler & Workers

The scheduler coordinates multiple workers executing parallel send/receive loops, providing backpressure, monotonic indexing, and response correlation.

Programmatic example:

```python
import asyncio
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.orchestration.scheduler import WorkerScheduler

async def main():
    config = RuntimeConfig(concurrency=4, queue_size=10, response_timeout_ms=1500)
    
    # transport_factory should return an instance implementing the Transport protocol
    scheduler = WorkerScheduler(
        config=config,
        transport_factory=lambda: MyL2CAPTransport(target_mac="00:11:22:33:44:55"),
        delay_ms=50.0,   # 50ms delay between packets
        rate_limit=20,   # Max 20 packets per second
    )
    
    # Spawn the workers and start the results processor
    await scheduler.start()
    
    # Submit packet payload (blocks if input queue is full, providing backpressure)
    idx = await scheduler.submit(b"\x06\x00\x01\x00\x03\x00\x00\x00")
    
    # Retrieve response (mapped by packet index, handling out-of-order arrival automatically)
    response = await scheduler.get_response(idx, timeout_seconds=5.0)
    print(f"Packet index: {response.packet_index}")
    print(f"Response: {response.response_payload}")
    
    # Gracefully shut down workers
    await scheduler.shutdown()

asyncio.run(main())
```
