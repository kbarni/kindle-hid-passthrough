#!/usr/bin/env python3
"""
Configuration

Configuration for Kindle HID Passthrough.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import configparser
import os
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    pass

__version__ = "2.7.0"

__all__ = ['config', 'Config', 'Protocol', 'get_fallback_hid_descriptor', 'normalize_addr', '__version__']


def normalize_addr(address: str) -> str:
    """Normalize Bluetooth address - strip /P suffix, uppercase."""
    return address.split('/')[0].upper()


class Protocol(Enum):
    """Supported Bluetooth protocols."""
    BLE = "ble"
    CLASSIC = "classic"


class Config:
    """Configuration manager"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if not self._loaded:
            self._load()
            self._loaded = True

    def _determine_base_path(self):
        """Determine base path dynamically.

        Priority:
        1. KINDLE_HID_BASE environment variable (set by C wrapper)
        2. Fallback to /mnt/us/kindle_hid_passthrough
        """
        if os.environ.get('KINDLE_HID_BASE'):
            self.base_path = os.environ['KINDLE_HID_BASE']
            return

        # Fallback
        self.base_path = '/mnt/us/kindle_hid_passthrough'

    def _load(self):
        """Load configuration from config.ini or use defaults"""
        self._determine_base_path()

        config_file = os.path.join(self.base_path, 'config.ini')
        self._parser = configparser.ConfigParser()

        if os.path.exists(config_file):
            self._parser.read(config_file)

        # Paths
        self.cache_dir = self._get('paths', 'cache_dir', f'{self.base_path}/cache')
        self.pairing_keys_file = os.path.join(self.cache_dir, 'pairing_keys.json')
        self.devices_config_file = self._get('paths', 'devices_config',
                                             f'{self.base_path}/devices.conf')
        self.log_file = self._get('logging', 'log_file', '/var/log/hid_passthrough.log')

        # Transport
        self.transport = self._get('transport', 'hci_transport', 'file:/dev/stpbt')

        # Timeouts (seconds)
        self.reconnect_delay = self._getint('connection', 'reconnect_delay', 5)
        self.hci_reset_timeout = self._getint('connection', 'hci_reset_timeout', 10)
        self.connect_timeout = self._getint('connection', 'connect_timeout', 30)
        self.transport_timeout = self._getint('connection', 'transport_timeout', 30)

        # Device identity
        self.device_name = self._get('device', 'name', 'Kindle-HID')
        self.device_address = self._get('device', 'address', 'F0:F0:F0:F0:F0:F0')

        # Protocol
        protocol_str = self._get('protocol', 'type', 'ble').lower()
        self.protocol = self._parse_protocol(protocol_str)

    def _parse_protocol(self, protocol_str: str) -> Protocol:
        """Parse protocol string to Protocol enum."""
        if protocol_str in ('classic', 'br/edr', 'bredr'):
            return Protocol.CLASSIC
        return Protocol.BLE

    def _get(self, section: str, key: str, default: str) -> str:
        try:
            return self._parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def _getint(self, section: str, key: str, default: int) -> int:
        try:
            return self._parser.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def get_device_config(self) -> Optional[tuple]:
        """Load first device address, protocol, and name from devices.conf.

        Returns:
            Tuple of (address, protocol, name) or None if not configured
        """
        devices = self.get_all_devices()
        return devices[0] if devices else None

    def get_all_devices(self) -> list:
        """Load all devices from devices.conf.

        Format:
            ADDRESS                    # Uses default protocol
            ADDRESS ble               # Explicit BLE
            ADDRESS classic           # Explicit Classic Bluetooth
            ADDRESS classic DeviceName # With device name
            # comment                  # Ignored
            * classic                  # Wildcard - accept any device

        Returns:
            List of tuples (address, protocol, name). Name may be None.
        """
        if not os.path.exists(self.devices_config_file):
            return []

        devices = []
        with open(self.devices_config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(None, 2)  # Split into max 3 parts
                    address = parts[0] if parts[0] == '*' else normalize_addr(parts[0])
                    protocol = self._parse_protocol(parts[1]) if len(parts) > 1 else self.protocol
                    name = parts[2] if len(parts) > 2 else None
                    devices.append((address, protocol, name))

        return devices

    def is_device_allowed(self, address: str) -> tuple:
        """Check if a device address is in the allowed list.

        Args:
            address: Device address to check (may have /P suffix from Bumble)

        Returns:
            Tuple of (allowed: bool, protocol: Protocol or None)
        """
        devices = self.get_all_devices()
        if not devices:
            return (False, None)

        addr_norm = normalize_addr(address)

        for dev_addr, protocol, _ in devices:
            if dev_addr == '*':
                return (True, protocol)
            if addr_norm == dev_addr:
                return (True, protocol)

        return (False, None)


def get_configured_protocols() -> set:
    """Get the set of protocols configured in devices.conf.

    Returns:
        Set of Protocol enums (may contain BLE, CLASSIC, or both)
    """
    devices = config.get_all_devices()
    return {d[1] for d in devices}


def get_fallback_hid_descriptor() -> bytes:
    """Return a generic fallback HID report descriptor.

    Used when SDP query or GATT read fails to get the real descriptor.
    Based on Xbox-style controller format with:
    - 4 axes (16-bit): left stick X/Y, right stick X/Y
    - 2 triggers (10-bit): LT, RT
    - D-pad as hat switch
    - 16 buttons
    """
    return bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop)
        0x09, 0x05,        # Usage (Gamepad)
        0xa1, 0x01,        # Collection (Application)
        0x85, 0x01,        #   Report ID (1)

        # 4 axes (16-bit each): LX, LY, RX, RY
        0x05, 0x01,        #   Usage Page (Generic Desktop)
        0x09, 0x30,        #   Usage (X) - Left stick X
        0x09, 0x31,        #   Usage (Y) - Left stick Y
        0x09, 0x32,        #   Usage (Z) - Right stick X
        0x09, 0x35,        #   Usage (Rz) - Right stick Y
        0x16, 0x00, 0x00,  #   Logical Minimum (0)
        0x26, 0xff, 0xff,  #   Logical Maximum (65535)
        0x75, 0x10,        #   Report Size (16)
        0x95, 0x04,        #   Report Count (4)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        # 2 triggers (10-bit): LT, RT
        0x05, 0x02,        #   Usage Page (Simulation Controls)
        0x09, 0xc5,        #   Usage (Brake) - LT
        0x09, 0xc4,        #   Usage (Accelerator) - RT
        0x16, 0x00, 0x00,  #   Logical Minimum (0)
        0x26, 0xff, 0x03,  #   Logical Maximum (1023)
        0x75, 0x10,        #   Report Size (16)
        0x95, 0x02,        #   Report Count (2)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        # D-pad as hat switch
        0x05, 0x01,        #   Usage Page (Generic Desktop)
        0x09, 0x39,        #   Usage (Hat Switch)
        0x15, 0x01,        #   Logical Minimum (1)
        0x25, 0x08,        #   Logical Maximum (8)
        0x35, 0x00,        #   Physical Minimum (0)
        0x46, 0x3b, 0x01,  #   Physical Maximum (315)
        0x65, 0x14,        #   Unit (Degrees)
        0x75, 0x08,        #   Report Size (8)
        0x95, 0x01,        #   Report Count (1)
        0x81, 0x42,        #   Input (Data, Variable, Null State)

        # 16 buttons
        0x05, 0x09,        #   Usage Page (Button)
        0x19, 0x01,        #   Usage Minimum (1)
        0x29, 0x10,        #   Usage Maximum (16)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x75, 0x01,        #   Report Size (1)
        0x95, 0x10,        #   Report Count (16)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        0xc0,              # End Collection
    ])


# Global singleton instance
config = Config()
