#!/usr/bin/env python3
"""
Kindle HID Passthrough - UHID Passthrough

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
    from host import HIDHost

    host = HIDHost()
    await host.run(device_address)
"""

from config import config, Protocol, __version__
from host import HIDHost
from logging_utils import log
from device_cache import DeviceCache

__all__ = [
    'HIDHost',
    'Protocol',
    'config',
    'log',
    'DeviceCache',
    '__version__',
]
