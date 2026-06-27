# Troubleshooting Guide

This guide details common adapter issues, tips for tuning SDP response timeouts, and how to calibrate crash detection settings to minimize false positives in SDPFuzz2.

## 1. Bluetooth Adapter & Connection Issues

### Adapter Status: "Host is down" or "Device or resource busy"
- **Cause**: The Bluetooth adapter is either powered off, blocked by rfkill, or already occupied by another process.
- **Solution**:
  1. Verify it is unblocked: `sudo rfkill unblock bluetooth`
  2. Bring the interface up: `sudo hciconfig hci0 up`
  3. Reset the adapter if it remains unresponsive:
     ```bash
     sudo hciconfig hci0 reset
     ```

### Socket Error: "Permission denied" or "Protocol not supported"
- **Cause**: Standard users lack permissions to bind raw Bluetooth sockets, or the kernel does not support L2CAP socket creation.
- **Solution**:
  - Run with `sudo`, or grant `CAP_NET_RAW` capability to the Python executable (see [Kali Setup Runbook](kali_setup_runbook.md)).
  - Ensure the host is running Linux; Bluetooth socket binding is not supported on Windows/macOS.

## 2. Tuning Response Timeouts

The default SDP response timeout is `1500 ms`. Slow or sleepy targets (like embedded microcontrollers or low-energy peripherals) may take longer to process and respond to fragments, causing false timeout flags.

### Tuning Recommendations
- **Calibrate Target Baseline**: Before starting a fuzz run, run the probe command with a generous timeout (e.g., 3000 ms) and verbose output to check target latency:
  ```bash
  sdpfuzz2 probe --index 1 --response-timeout-ms 3000 --debug
  ```
- **Fuzzing Timeout Thresholds**:
  - If a target is close and responsive: use `1000` to `1500` ms to maximize fuzzing speed.
  - If a target experiences occasional packet loss or latency spikes: increase to `2000` or `3000` ms to prevent false crash detection.

## 3. Crash Detection Calibration

The `CrashDetector` classifies failures into confidence categories (Medium, High, Unknown) based on consecutive timeouts and connection failures. You can configure these thresholds in [src/sdpfuzz2/cli.py](file:///D:/Shared/sdpfuzz2/src/sdpfuzz2/cli.py) or `RuntimeConfig`.

### Heuristics Tuning

1. **Consecutive Timeouts (`timeout_threshold`)**:
   - *Default*: `3` consecutive timeouts.
   - *High-noise environment*: Increase to `5`. This prevents a burst of radio interference or packet drops from being falsely identified as a crash.
   - *Low-noise wired laboratory*: Set to `2` for faster crash detection.

2. **Connection Failures (`connection_failure_threshold`)**:
   - *Default*: `2` consecutive refused/reset connections.
   - *Behavior*: A connection refused (`ECONNREFUSED`) or reset (`ECONNRESET`) usually indicates the target's Bluetooth stack has crashed or is rebooting.
   - *Calibration*: If the target frequently resets connections under stress but recovers instantly, set to `3` or `4` to filter out minor glitches.

3. **Multi-Worker Corroboration (`worker_agreement_threshold`)**:
   - *Default*: `0.5` (50% of active workers must agree on the failure).
   - *Calibration*: When fuzzing concurrently with high concurrency (e.g. `--concurrency 8`), a local adapter issue might affect one worker. High corroboration requirements (e.g. `0.75` or `0.8`) ensure that most workers agree the device is unresponsive before halting, eliminating isolated worker bottlenecks as false crash reports.
