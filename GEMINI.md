# Gemini Context: Kindle HID Passthrough

## Project Overview
Kindle HID Passthrough is a userspace Bluetooth HID host specifically designed for Amazon Kindle e-readers. It allows connecting Bluetooth HID devices (gamepads, keyboards, remotes) and passing their input directly to the Linux kernel via the UHID (Userspace HID) subsystem.

### Main Technologies
- **Python 3.10+**: Core implementation language.
- **Google Bumble**: A userspace Bluetooth stack used to bypass the Kindle's often buggy or restricted kernel Bluetooth drivers.
- **Linux UHID**: Used to create virtual input devices in `/dev/input/eventX` from userspace.
- **Just**: Command runner for deployment and development tasks.

### Architecture
1. **Transport**: Communicates with the Bluetooth hardware via `/dev/stpbt` (MediaTek-specific on many Kindles).
2. **Bluetooth Stack**: Bumble handles the L2CAP (Classic) and GATT (BLE) protocols in userspace.
3. **HID Processing**: Receives raw HID reports from the device.
4. **UHID Forwarding**: Forwards reports to `/dev/uhid`, which creates a native Linux input device.
5. **Daemon**: A persistent manager (`daemon.py`) ensures auto-reconnection and handles authentication failures.

## Building and Running

### Prerequisites
- Root access on Kindle (USBNetwork).
- Python 3.10 runtime (usually bundled in the release or at `/mnt/us/python3.10-kindle/`).
- `/dev/stpbt` and `/dev/uhid` nodes available on the Kindle.

### Key Commands (via `just`)
- **Deploy**: `just deploy` - Copies source files, udev rules, and upstart configs to the Kindle.
- **Pairing**:
    - `just pair-classic`: Interactive pairing for Classic Bluetooth devices.
    - `just pair-ble`: Interactive pairing for BLE devices.
- **Execution**:
    - `just start`: Starts the Upstart service (`hid-passthrough`).
    - `just stop`: Stops the service.
    - `just restart`: Restarts the service.
    - `just run`: Runs the application manually for debugging.
- **Monitoring**:
    - `just logs`: Follows `/var/log/hid_passthrough.log`.
    - `just devices`: Lists devices configured in `devices.conf`.

### Configuration Files
- `devices.conf`: Stores paired device addresses and protocols (e.g., `XX:XX:XX:XX:XX:XX ble`).
- `config.ini`: General configuration (timeouts, paths, log levels).
- `cache/pairing_keys.json`: Persists Bluetooth link keys.

## Development Conventions

### Code Style
- **Asynchronous**: Uses `asyncio` extensively for Bluetooth communication and UHID handling.
- **Linting**: Uses `ruff` for linting and formatting (see `ruff.toml`).
- **Pathing**: The project assumes a base path of `/mnt/us/kindle_hid_passthrough` on the Kindle.

### Project Structure
- `kindle_hid_passthrough/main.py`: Entry point for CLI arguments and pairing mode.
- `kindle_hid_passthrough/daemon.py`: Logic for the persistent background service.
- `kindle_hid_passthrough/host.py`: Implements the Bumble-based Bluetooth host.
- `kindle_hid_passthrough/uhid_handler.py`: Manages the creation of `/dev/uhid` devices.
- `kindle_hid_passthrough/scanner.py`: Handles Bluetooth device discovery.
- `kindle_hid_passthrough/config.py`: Centralized configuration management.
- `assets/`: Contains Kindle-specific system files (udev, upstart, KUAL menus).

### Testing & Verification
- `just check`: Runs `py_compile` on all Python files to ensure syntax correctness.
- Manual testing on device is the primary verification method due to hardware dependencies (`/dev/stpbt`).
