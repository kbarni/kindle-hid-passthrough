#!/usr/bin/env python3
"""
Unified HID Host - UHID Passthrough

HID device support for Linux using Google Bumble.
Supports both Bluetooth Low Energy (BLE) and Classic Bluetooth (BR/EDR).
Forwards HID reports to Linux via UHID.

Usage:
    # Interactive pairing
    python main.py --pair --protocol classic

    # Run (connect to configured device)
    python main.py

    # Run as daemon
    python main.py --daemon

    # Programmatic use
    from unified_host import UnifiedHIDHost
    from config import create_host, Protocol

    host = create_host()
    await host.run(device_address)
"""

__version__ = "2.4.0"

from unified_host import UnifiedHIDHost
from config import config, Protocol, create_host
from logging_utils import log
from device_cache import DeviceCache

__all__ = [
    'UnifiedHIDHost',
    'Protocol',
    'create_host',
    'config',
    'log',
    'DeviceCache',
    '__version__',
]
