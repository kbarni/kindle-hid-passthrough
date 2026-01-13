#!/usr/bin/env python3
"""
BLE HID Host - Pure UHID Passthrough

BLE HID host implementation using Google Bumble.
Connects to BLE HID devices, discovers GATT services, and forwards
all HID reports directly to Linux via UHID.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

__version__ = "2.1.0"

import asyncio
from typing import Optional

from bumble.device import Device, Peer
from bumble.hci import Address, HCI_Reset_Command, OwnAddressType
from bumble.gatt import (
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_HUMAN_INTERFACE_DEVICE_SERVICE,
    GATT_REPORT_MAP_CHARACTERISTIC,
    GATT_REPORT_CHARACTERISTIC,
    GATT_REPORT_REFERENCE_DESCRIPTOR,
    GATT_HID_INFORMATION_CHARACTERISTIC,
    GATT_HID_CONTROL_POINT_CHARACTERISTIC,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    GATT_BOOT_KEYBOARD_INPUT_REPORT_CHARACTERISTIC,
    GATT_BOOT_KEYBOARD_OUTPUT_REPORT_CHARACTERISTIC,
)
from bumble.transport import open_transport
from bumble.core import InvalidStateError, ProtocolError

from config import config
from logging_utils import log
from device_cache import DeviceCache
from pairing import create_pairing_config, create_keystore
from state_machine import StateMachine, HostState

__all__ = ['BLEHIDHost', '__version__']

# HID Report Types
HID_REPORT_TYPE_INPUT = 1
HID_REPORT_TYPE_OUTPUT = 2
HID_REPORT_TYPE_FEATURE = 3


class BLEHIDHost:
    """BLE HID Host with pure UHID passthrough.

    This host:
    1. Scans for and connects to BLE HID devices
    2. Discovers GATT HID service
    3. Gets report descriptor from Report Map characteristic
    4. Creates UHID device and forwards all reports

    Uses StateMachine for explicit state management.
    """

    PROTOCOL_NAME = "BLE"

    def __init__(self, transport_spec: str = None):
        """Initialize BLE HID Host.

        Args:
            transport_spec: HCI transport (default: from config)
        """
        self.transport_spec = transport_spec or config.transport
        self.transport = None
        self.device = None
        self.connection = None
        self.peer = None

        # State machine
        self.state_machine = StateMachine()

        # Device state
        self.current_device_address = None
        self.device_name = None
        self.report_map: Optional[bytes] = None
        self.hid_reports = {}  # report_id -> characteristic

        # Components
        self.keystore = create_keystore(config.pairing_keys_file)
        self.device_cache = DeviceCache(config.cache_dir)

        # UHID
        self.uhid_device = None
        self._uhid_available = False
        try:
            from uhid_handler import UHIDDevice, Bus, UHIDError
            self._UHIDDevice = UHIDDevice
            self._Bus = Bus
            self._UHIDError = UHIDError
            self._uhid_available = True
        except ImportError:
            log.warning("UHID support not available")

        # Events
        self._disconnection_event = None

    @property
    def state(self) -> HostState:
        """Current host state."""
        return self.state_machine.state

    @property
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self.state_machine.is_connected

    async def start(self):
        """Initialize the Bumble device and BLE stack."""
        self.state_machine.transition(HostState.STARTING)

        log.info(f"BLE HID Host v{__version__}")
        log.info("Opening transport...")

        try:
            self.transport = await asyncio.wait_for(
                open_transport(self.transport_spec),
                timeout=config.transport_timeout
            )
        except asyncio.TimeoutError:
            self.state_machine.transition(HostState.ERROR, "Transport timeout")
            log.error(f"Transport open timed out after {config.transport_timeout}s")
            raise

        self.device = Device.with_hci(
            config.device_name,
            config.device_address,
            self.transport.source,
            self.transport.sink
        )

        self.device.keystore = self.keystore
        self.device.pairing_config_factory = lambda conn: create_pairing_config()

        log.info("Sending HCI Reset...")
        try:
            await asyncio.wait_for(
                self.device.host.send_command(HCI_Reset_Command()),
                timeout=config.hci_reset_timeout
            )
            log.success("HCI Reset successful")
        except asyncio.TimeoutError:
            self.state_machine.transition(HostState.ERROR, "HCI Reset timeout")
            log.error("HCI Reset timed out")
            raise

        await self.device.power_on()
        log.success(f"Device powered on: {self.device.public_address}")

    async def pair_device(self, address: str) -> bool:
        """Pair with a device (first-time setup).

        Args:
            address: Device address to pair with

        Returns:
            True if pairing successful
        """
        self.state_machine.transition(HostState.CONNECTING)
        log.info(f"Pairing with {address}...")

        target = Address(address)
        try:
            self.connection = await asyncio.wait_for(
                self.device.connect(
                    target,
                    own_address_type=OwnAddressType.PUBLIC
                ),
                timeout=config.connect_timeout,
            )
        except Exception as e:
            self.state_machine.transition(HostState.ERROR, f"Connection failed: {e}")
            log.error(f"Connection failed: {e}")
            return False

        self.peer = Peer(self.connection)
        log.success(f"Connected to {address}")

        try:
            self.state_machine.transition(HostState.AUTHENTICATING)
            log.info("Initiating pairing...")
            await self.connection.pair()
            log.success("Pairing complete!")

            # Discover and cache HID data
            self.state_machine.transition(HostState.DISCOVERING_SERVICES)
            await self._discover_and_cache_hid(address)

            self.state_machine.transition(HostState.IDLE)
            return True
        except Exception as e:
            self.state_machine.transition(HostState.ERROR, f"Pairing failed: {e}")
            log.error(f"Pairing failed: {e}")
            return False
        finally:
            if self.connection:
                try:
                    await self.connection.disconnect()
                except Exception:
                    pass
                self.connection = None
                self.peer = None

    async def _discover_and_cache_hid(self, address: str):
        """Discover HID service and cache data."""
        if not self.peer:
            return

        await self.peer.discover_services()

        # Read device name
        await self._read_device_name()

        # Find HID service
        hid_services = [s for s in self.peer.services if s.uuid == GATT_HUMAN_INTERFACE_DEVICE_SERVICE]
        if not hid_services:
            log.warning("HID service not found")
            return

        hid_service = hid_services[0]
        await self.peer.discover_characteristics(service=hid_service)

        # Read report map
        for char in hid_service.characteristics:
            if char.uuid == GATT_REPORT_MAP_CHARACTERISTIC:
                try:
                    value = await self.peer.read_value(char)
                    self.report_map = bytes(value)
                    log.success(f"Got report descriptor: {len(self.report_map)} bytes")
                except Exception as e:
                    log.warning(f"Failed to read report map: {e}")

        # Cache data
        if self.report_map:
            self.device_cache.save(address, {
                'report_map': self.report_map.hex(),
                'device_name': self.device_name
            })
            log.success("Cached HID data for future connections")

    async def _read_device_name(self):
        """Read device name from Generic Access Service."""
        try:
            for service in self.peer.services:
                if service.uuid == GATT_GENERIC_ACCESS_SERVICE:
                    await self.peer.discover_characteristics(service=service)
                    for char in service.characteristics:
                        if char.uuid == GATT_DEVICE_NAME_CHARACTERISTIC:
                            value = await self.peer.read_value(char)
                            self.device_name = bytes(value).decode('utf-8', errors='replace')
                            log.info(f"Device name: {self.device_name}")
                            return
        except Exception as e:
            log.warning(f"Could not read device name: {e}")

    async def run(self, target_address: str):
        """Main run loop - connect and forward reports.

        Args:
            target_address: Device address to connect to
        """
        self._disconnection_event = asyncio.Event()

        await self.start()

        # Load cached data
        cache = self.device_cache.load(target_address)
        if cache:
            if 'report_map' in cache:
                self.report_map = bytes.fromhex(cache['report_map'])
                log.success(f"Loaded cached descriptor ({len(self.report_map)} bytes)")
            if 'device_name' in cache:
                self.device_name = cache['device_name']

        # Connect
        self.state_machine.transition(HostState.CONNECTING)
        log.info(f"Connecting to {target_address}...")
        target = Address(target_address)
        try:
            self.connection = await asyncio.wait_for(
                self.device.connect(target, own_address_type=OwnAddressType.PUBLIC),
                timeout=config.connect_timeout
            )
        except asyncio.TimeoutError:
            self.state_machine.transition(HostState.ERROR, "Connection timeout")
            raise ProtocolError(f"Connection timeout after {config.connect_timeout}s")

        self.peer = Peer(self.connection)
        self.current_device_address = target_address
        log.success(f"Connected to {target_address}")

        # Set up disconnection handler
        self.connection.on('disconnection', self._on_disconnection)

        # Restore bonding or pair
        self.state_machine.transition(HostState.AUTHENTICATING)
        await self._restore_or_pair()

        # Discover HID service
        self.state_machine.transition(HostState.DISCOVERING_SERVICES)
        await self._discover_hid_service()

        # Create UHID device
        if not self.report_map:
            self.state_machine.transition(HostState.ERROR, "No report descriptor")
            raise InvalidStateError("No report descriptor available")

        self._create_uhid_device()

        # Subscribe to reports
        await self._subscribe_to_reports()

        self.state_machine.transition(HostState.CONNECTED)
        log.success(f"\n[BLE] Receiving HID reports. Press Ctrl+C to exit.")

        # Wait for disconnection
        await self._disconnection_event.wait()

    def _on_disconnection(self, reason):
        """Handle device disconnection."""
        log.warning(f"Device disconnected (reason={reason})")
        self.state_machine.transition(HostState.IDLE)
        self._disconnection_event.set()

    async def _restore_or_pair(self):
        """Restore bonding or initiate new pairing."""
        if self.device.keystore:
            try:
                keys = await self.device.keystore.get(str(self.connection.peer_address))
                if keys:
                    log.info("Restoring bonding...")
                    await self.connection.encrypt()
                    log.success("Bonding restored")
                    return
            except Exception as e:
                log.warning(f"Bonding restore failed: {e}")

        log.info("Initiating pairing...")
        await self.connection.pair()
        log.success("Pairing complete")

    async def _discover_hid_service(self):
        """Discover GATT HID service."""
        await self.peer.discover_services()

        if not self.device_name:
            await self._read_device_name()

        hid_services = [s for s in self.peer.services if s.uuid == GATT_HUMAN_INTERFACE_DEVICE_SERVICE]
        if not hid_services:
            raise InvalidStateError("HID service not found")

        hid_service = hid_services[0]
        log.success("Found HID service")

        await self.peer.discover_characteristics(service=hid_service)

        for char in hid_service.characteristics:
            if char.uuid == GATT_REPORT_MAP_CHARACTERISTIC and not self.report_map:
                try:
                    value = await self.peer.read_value(char)
                    self.report_map = bytes(value)
                    log.success(f"Got report descriptor: {len(self.report_map)} bytes")

                    # Cache it
                    self.device_cache.save(self.current_device_address, {
                        'report_map': self.report_map.hex(),
                        'device_name': self.device_name
                    })
                except Exception as e:
                    log.warning(f"Failed to read report map: {e}")

            elif char.uuid == GATT_REPORT_CHARACTERISTIC:
                await self._process_report_char(char)

    async def _process_report_char(self, char):
        """Process a Report characteristic."""
        await self.peer.discover_descriptors(characteristic=char)

        report_id = 0
        report_type = HID_REPORT_TYPE_INPUT

        for desc in char.descriptors:
            if desc.type == GATT_REPORT_REFERENCE_DESCRIPTOR:
                try:
                    ref = await self.peer.read_value(desc)
                    if len(ref) >= 2:
                        report_id = ref[0]
                        report_type = ref[1]
                except Exception:
                    pass

        if report_type == HID_REPORT_TYPE_INPUT:
            self.hid_reports[report_id] = char
            log.info(f"Found input report {report_id}")

    async def _subscribe_to_reports(self):
        """Subscribe to HID input report notifications."""
        for report_id, char in self.hid_reports.items():
            try:
                # Capture report_id in lambda closure
                await self.peer.subscribe(
                    char, 
                    lambda value, rid=report_id: self._on_hid_report(rid, value)
                )
                log.success(f"Subscribed to report {report_id}")
            except Exception as e:
                log.warning(f"Failed to subscribe to report {report_id}: {e}")

    def _on_hid_report(self, report_id, value):
        """Handle incoming HID report."""
        data = bytes(value)
        if self.uhid_device:
            try:
                # Prepend report ID for UHID
                self.uhid_device.send_input(bytes([report_id]) + data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _create_uhid_device(self):
        """Create UHID virtual device."""
        if not self._uhid_available:
            log.warning("UHID not available")
            return

        if not self.report_map:
            log.warning("No report descriptor for UHID")
            return

        try:
            name = self.device_name or "BLE HID Device"
            self.uhid_device = self._UHIDDevice(
                name=name,
                report_descriptor=self.report_map,
                bus=self._Bus.BLUETOOTH,
                vendor=0,
                product=0,
            )
            log.success(f"UHID device created: {name}")
        except Exception as e:
            log.error(f"Failed to create UHID device: {e}")

    async def cleanup(self):
        """Clean up resources."""
        self.state_machine.transition(HostState.DISCONNECTING)

        if self.uhid_device:
            try:
                self.uhid_device.destroy()
            except Exception:
                pass
            self.uhid_device = None

        # Check if HCI connection is still valid before disconnecting
        connection_alive = (self.connection is not None and
                           hasattr(self.connection, 'handle') and
                           self.connection.handle is not None)

        if connection_alive:
            try:
                await self.connection.disconnect()
            except Exception:
                pass
        self.connection = None

        if self.transport:
            await self.transport.close()

        self.state_machine.reset()

    async def wait_for_state(self, *states: HostState, timeout: float = None) -> HostState:
        """Wait until host reaches one of the specified states.

        Args:
            *states: Target states to wait for
            timeout: Maximum wait time in seconds

        Returns:
            The state that was reached
        """
        return await self.state_machine.wait_for(*states, timeout=timeout)
