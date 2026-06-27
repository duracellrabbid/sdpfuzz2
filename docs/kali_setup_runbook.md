# Kali Linux Setup Runbook

This guide covers setting up your Kali Linux environment, configuring the Bluetooth adapter, managing permissions, and configuring BlueZ to run SDPFuzz2.

## 1. Bluetooth Adapter Hardware and Kernel Check

SDPFuzz2 requires an adapter that supports raw L2CAP connections and scanning.

1. **Plug in your USB Bluetooth Adapter**.
2. **Verify the hardware is detected by the kernel**:
   ```bash
   lsusb | grep -i bluetooth
   # Output should show your USB Bluetooth controller details
   ```
3. **Verify the kernel modules are loaded**:
   ```bash
   lsmod | grep bluetooth
   # Ensure 'bluetooth', 'rfcomm', 'l2cap' or similar modules are loaded
   ```

## 2. BlueZ Service Status

BlueZ is the Linux Bluetooth stack. Ensure it is enabled and running.

```bash
# Check service status
sudo systemctl status bluetooth

# Start if stopped
sudo systemctl start bluetooth

# Enable on boot
sudo systemctl enable bluetooth
```

## 3. Bringing the Adapter Up and Scanning

Use standard BlueZ utilities to verify the adapter can scan and discover target devices.

1. **Show local adapter configuration**:
   ```bash
   hciconfig -a
   # Note the adapter interface name (typically hci0)
   ```
2. **Bring the adapter UP**:
   ```bash
   sudo hciconfig hci0 up
   ```
3. **Unblock Bluetooth (RFKill)**:
   ```bash
   sudo rfkill unblock bluetooth
   ```
4. **Scan for target devices interactively**:
   ```bash
   bluetoothctl
   [bluetooth]# power on
   [bluetooth]# scan on
   # Note down MAC addresses of target Bluetooth devices
   [bluetooth]# quit
   ```

## 4. Permissions & Non-Root Execution

By default, Linux requires root privileges to open raw L2CAP sockets (`SOCK_SEQPACKET` with `BTPROTO_L2CAP`) and to access the system D-Bus.

### Option A: Run as Root (Easiest for Lab Environments)
Run SDPFuzz2 CLI commands with `sudo`:
```bash
sudo sdpfuzz2 discover
sudo sdpfuzz2 fuzz --target AA:BB:CC:DD:EE:FF --mode random-bytes
```

### Option B: Grant Capabilities to the Python Executable (Recommended for Devs)
If you want to run SDPFuzz2 without `sudo` (e.g. from within a virtual environment), you can grant the network raw socket capability directly to your Python binary.

1. **Locate the python binary in your virtual environment**:
   ```bash
   which python
   # Example: /home/kali/sdpfuzz2/.venv/bin/python
   ```
2. **Grant `CAP_NET_RAW` capability**:
   ```bash
   sudo setcap cap_net_raw+eip /home/kali/sdpfuzz2/.venv/bin/python
   ```
3. **Allow D-Bus system access**:
   Ensure your current user is in the `bluetooth` group:
   ```bash
   sudo usermod -aG bluetooth $USER
   # Reboot or log out and log back in for group changes to take effect
   ```

## 5. Troubleshooting BlueZ Main Configuration

If the adapter fails to connect or scan, verify `/etc/bluetooth/main.conf`.
Ensure the following settings are active (uncommented):
```ini
[General]
# Allow/disable specific profiles if needed
# Enable=Source,Sink,Media,Socket
```
Restart BlueZ after any configuration changes:
```bash
sudo systemctl restart bluetooth
```
