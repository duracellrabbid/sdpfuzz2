# Fuzzer Log Schema & Analysis Guide

SDPFuzz2 records fuzzing session logs in a structured, serialized JSON format verified via Pydantic. This document defines the schema fields and explains how to parse and analyze logs.

## 1. Schema Definitions

The root object of a log file represents a `FuzzingSession`. Below are the fields present in the JSON output:

| Field | Type | Description |
|---|---|---|
| `device_name` | string | Normalized name of the target Bluetooth device. |
| `device_mac_address` | string | Target Bluetooth MAC address (`XX:XX:XX:XX:XX:XX`). |
| `start_time` | string | ISO-8601 UTC timestamp when the fuzzing session started. |
| `end_time` | string | ISO-8601 UTC timestamp when the session completed or aborted. |
| `fuzz_mode` | string | Fuzzing strategy mode selected for the run. |
| `run_id` | string (optional) | Monotonically generated or configured unique run identifier. |
| `summary_counters` | object | Summary of sent/received packets and detected crashes. |
| `logs` | array | Sequential list of individual packet exchanges. |

### `summary_counters` Schema:
- `packets_sent` (int): Total number of fuzz requests sent.
- `packets_received` (int): Total number of responses received.
- `crashes_detected` (int): Number of crash events confirmed.

### `logs` List Entry Schema:
- `packet_index` (int): Monotonically increasing packet index.
- `request_packet_hex` (string): Hexadecimal representation of the request packet sent.
- `response_packet_hex` (string): Hexadecimal representation of the response packet received (empty if timeout occurred).
- `crash` (int): `1` if a crash event was detected immediately after this request, otherwise `0`.
- `worker_id` (int, optional): The ID of the worker that processed this request.
- `in_flight_at_send` (int, optional): The number of concurrent packets in flight when this request was sent.

---

## 2. Example Log Object

```json
{
  "device_name": "Speaker Target",
  "device_mac_address": "AA:BB:CC:DD:EE:FF",
  "start_time": "2026-06-27T12:00:00Z",
  "end_time": "2026-06-27T12:00:15Z",
  "fuzz_mode": "random-bytes",
  "summary_counters": {
    "packets_sent": 105,
    "packets_received": 102,
    "crashes_detected": 1
  },
  "logs": [
    {
      "packet_index": 1,
      "request_packet_hex": "060001000f3503191101ffff35050a0000ffff00",
      "response_packet_hex": "070001000b0006350409000100",
      "crash": 0,
      "worker_id": 0,
      "in_flight_at_send": 1
    },
    {
      "packet_index": 105,
      "request_packet_hex": "060069000a3503191101ffff35029999",
      "response_packet_hex": "",
      "crash": 1,
      "worker_id": 1,
      "in_flight_at_send": 3
    }
  ]
}
```

---

## 3. Log Analysis Snippet

You can analyze logs using python to quickly locate packets that triggered a crash or timeout.

```python
import json
import sys

def analyze_log(filepath: str):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"--- Fuzz Run Analysis for {data['device_name']} ({data['device_mac_address']}) ---")
    print(f"Mode: {data['fuzz_mode']}")
    print(f"Packets Sent: {data['summary_counters']['packets_sent']}")

    # Locate all packets that triggered a crash
    crash_packets = [log for log in data['logs'] if log['crash'] == 1]

    if crash_packets:
        print(f"\n[!] Detected {len(crash_packets)} packets associated with crashes:")
        for log in crash_packets:
            print(f"  - Packet Index: {log['packet_index']}")
            print(f"    Request Hex:  {log['request_packet_hex']}")
            print(f"    Worker ID:    {log['worker_id']}")
    else:
        print("\n[+] No crashes recorded in this log.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_log.py <path_to_log.json>")
    else:
        analyze_log(sys.argv[1])
```
