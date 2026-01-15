#!/usr/bin/env python3
"""
Unified HID Host - Supports both BLE and Classic Bluetooth

Handles mixed-protocol device configurations by running both
BLE and Classic handlers on a single Bumble Device.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import asyncio
from typing import Optional, List, Tuple
from dataclasses import dataclass

from bumble.device import Device, Peer
from bumble.hci import (
    Address,
    HCI_Reset_Command,
    HCI_Write_Scan_Enable_Command,
    HCI_Write_Class_Of_Device_Command,
    HCI_Write_Local_Name_Command,
    OwnAddressType,
)
from bumble.transport import open_transport
from bumble.hid import Host as HIDHost, Message, HID_CONTROL_PSM, HID_INTERRUPT_PSM
from bumble.core import BT_BR_EDR_TRANSPORT, BT_HUMAN_INTERFACE_DEVICE_SERVICE, InvalidStateError
from bumble.sdp import Client as SDPClient
from bumble.gatt import (
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_HUMAN_INTERFACE_DEVICE_SERVICE,
    GATT_REPORT_MAP_CHARACTERISTIC,
    GATT_REPORT_CHARACTERISTIC,
    GATT_REPORT_REFERENCE_DESCRIPTOR,
)

from config import config, Protocol, get_fallback_hid_descriptor
from logging_utils import log
from pairing import create_pairing_config, create_keystore
from device_cache import DeviceCache

__all__ = ['UnifiedHIDHost']

# HID Report Types
HID_REPORT_TYPE_INPUT = 1


@dataclass
class DeviceConfig:
    """Device configuration from devices.conf."""
    address: str
    protocol: Protocol
    name: Optional[str] = None


class UnifiedHIDHost:
    """Unified HID Host supporting both BLE and Classic Bluetooth.

    This host:
    1. Parses device configs and groups by protocol
    2. Creates a single Bumble Device with both protocols enabled
    3. Runs handlers concurrently:
       - Classic: page scan (passive) + active connection attempts
       - BLE: scan for known addresses and connect
    4. First successful connection wins
    5. Creates UHID device and forwards reports
    """

    PROTOCOL_NAME = "Unified"

    # Active connection timing
    ACTIVE_DELAY = 2.0
    ACTIVE_RETRY_INTERVAL = 5.0
    ACTIVE_CONNECT_TIMEOUT = 10  # In 0.5s increments

    def __init__(self, transport_spec: str = None):
        """Initialize Unified HID Host.

        Args:
            transport_spec: HCI transport (default: from config)
        """
        self.transport_spec = transport_spec or config.transport
        self.transport = None
        self.device = None
        self.connection = None
        self.peer = None  # For BLE

        # Protocol-specific
        self.hid_host = None  # For Classic
        self.connected_protocol = None

        # Device state
        self.current_device_address = None
        self.device_name = None
        self.report_map: Optional[bytes] = None
        self.hid_reports = {}  # For BLE

        # Device configs
        self.classic_devices: List[DeviceConfig] = []
        self.ble_devices: List[DeviceConfig] = []
        self._keystore_addresses: set = set()

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
        self._connection_future = None
        self._last_report = None
        self._auth_failure_address = None  # Track address for auth failure retry

    def _parse_devices(self):
        """Parse devices from config and group by protocol."""
        devices = config.get_all_devices()
        self.classic_devices = []
        self.ble_devices = []

        for addr, protocol, name in devices:
            dev = DeviceConfig(address=addr, protocol=protocol, name=name)
            if protocol == Protocol.CLASSIC:
                self.classic_devices.append(dev)
            else:
                self.ble_devices.append(dev)

        log.info(f"Devices: {len(self.classic_devices)} Classic, {len(self.ble_devices)} BLE")

    async def start(self):
        """Initialize the Bumble device with both protocols."""
        from __init__ import __version__

        log.info(f"Unified HID Host v{__version__}")
        log.info("Opening transport...")

        try:
            self.transport = await asyncio.wait_for(
                open_transport(self.transport_spec),
                timeout=config.transport_timeout
            )
        except asyncio.TimeoutError:
            log.error(f"Transport open timed out after {config.transport_timeout}s")
            raise

        self.device = Device.with_hci(
            config.device_name,
            config.device_address,
            self.transport.source,
            self.transport.sink
        )

        # Enable both protocols
        self.device.classic_enabled = bool(self.classic_devices)
        self.device.le_enabled = bool(self.ble_devices)

        self.device.keystore = self.keystore
        self.device.pairing_config_factory = lambda conn: create_pairing_config()

        if self.classic_devices:
            self.device.classic_ssp_enabled = True
            self.device.classic_sc_enabled = True

        log.info("Sending HCI Reset...")
        try:
            await asyncio.wait_for(
                self.device.host.send_command(HCI_Reset_Command()),
                timeout=config.hci_reset_timeout
            )
            log.success("HCI Reset successful")
            await asyncio.sleep(0.2)
        except asyncio.TimeoutError:
            log.error("HCI Reset timed out")
            raise

        await self.device.power_on()
        log.success(f"Device powered on: {self.device.public_address}")

        # Classic-specific setup
        if self.classic_devices:
            class_of_device = 0x000104  # Computer/Desktop
            await self.device.host.send_command(
                HCI_Write_Class_Of_Device_Command(class_of_device=class_of_device),
                check_result=True
            )
            log.info(f"Classic enabled: CoD 0x{class_of_device:06X}")

            local_name_bytes = config.device_name.encode('utf-8') + b'\x00'
            await self.device.host.send_command(
                HCI_Write_Local_Name_Command(local_name=local_name_bytes),
                check_result=True
            )

        if self.ble_devices:
            log.info("BLE enabled")

        # Load keystore addresses
        await self._load_keystore_addresses()

    async def _load_keystore_addresses(self):
        """Load addresses from keystore for connection filtering."""
        self._keystore_addresses = set()
        if self.keystore:
            try:
                keys = await self.keystore.get_all()
                if keys:
                    for entry in keys:
                        addr = str(entry[0]) if isinstance(entry, (list, tuple)) else str(entry)
                        self._keystore_addresses.add(addr.split('/')[0].upper())
                    log.info(f"Keystore has {len(self._keystore_addresses)} entries")
            except Exception as e:
                log.warning(f"Failed to load keystore: {e}")

    def _format_device(self, addr: str) -> str:
        """Format device address with name if available."""
        norm = addr.split('/')[0].upper()
        for dev in self.classic_devices + self.ble_devices:
            if dev.address.split('/')[0].upper() == norm:
                if dev.name:
                    return f"{dev.name} ({addr})"
        return addr

    async def run(self, target_address: str = None):
        """Main run loop - handle both protocols concurrently.

        Args:
            target_address: Optional specific address (uses devices.conf if None)
        """
        self._disconnection_event = asyncio.Event()
        self._connection_future = asyncio.get_event_loop().create_future()

        self._parse_devices()
        await self.start()

        # Load cached descriptors
        for dev in self.classic_devices + self.ble_devices:
            if dev.address != '*':
                cache = self.device_cache.load(dev.address)
                if cache and 'report_map' in cache:
                    log.info(f"Cached descriptor for {self._format_device(dev.address)}")

        # Start protocol handlers
        tasks = []

        if self.classic_devices:
            tasks.append(asyncio.create_task(
                self._run_classic_handler(),
                name="classic_handler"
            ))

        if self.ble_devices:
            tasks.append(asyncio.create_task(
                self._run_ble_handler(),
                name="ble_handler"
            ))

        if not tasks:
            log.error("No devices configured")
            return

        log.info(f"[Unified] Waiting for connection (Classic: {len(self.classic_devices)}, BLE: {len(self.ble_devices)})")

        try:
            # Wait for first connection
            await asyncio.wait_for(self._connection_future, timeout=60.0)
        except asyncio.TimeoutError:
            log.warning("Connection timeout - no device connected")
            raise InvalidStateError("No device connected within timeout")
        finally:
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        # Connection established - now handle based on protocol
        if self.connected_protocol == Protocol.CLASSIC:
            await self._handle_classic_connection()
        else:
            await self._handle_ble_connection()

        proto_name = self.connected_protocol.value.upper()
        log.success(f"\n[{proto_name}] Receiving HID reports. Press Ctrl+C to exit.")

        # Wait for disconnection with retry on auth failure
        max_auth_retries = 3
        auth_retry_count = 0

        while True:
            await self._disconnection_event.wait()

            # Check if this was an auth failure that we should retry
            if self._auth_failure_address and auth_retry_count < max_auth_retries:
                auth_retry_count += 1
                failed_addr = self._auth_failure_address
                self._auth_failure_address = None

                log.info(f"[Classic] Auth failure retry {auth_retry_count}/{max_auth_retries}")

                # Clear the stale key
                await self.clear_stale_key(failed_addr)

                # Clean up current connection state
                if self.hid_host:
                    self.hid_host = None
                self.connection = None
                self.connected_protocol = None
                self.current_device_address = None

                # Destroy UHID device if it was created
                if self.uhid_device:
                    try:
                        self.uhid_device.destroy()
                    except Exception:
                        pass
                    self.uhid_device = None

                # Reset events for retry
                self._disconnection_event.clear()
                self._connection_future = asyncio.get_event_loop().create_future()

                # Wait before retry
                log.info("[Classic] Waiting 3s before retry...")
                await asyncio.sleep(3.0)

                # Re-start Classic handler only
                log.info("[Classic] Restarting connection handler...")
                classic_task = asyncio.create_task(
                    self._run_classic_handler(),
                    name="classic_handler_retry"
                )

                try:
                    await asyncio.wait_for(self._connection_future, timeout=60.0)
                except asyncio.TimeoutError:
                    log.warning("[Classic] Retry connection timeout")
                    classic_task.cancel()
                    try:
                        await classic_task
                    except asyncio.CancelledError:
                        pass
                    break
                finally:
                    if not classic_task.done():
                        classic_task.cancel()
                        try:
                            await classic_task
                        except asyncio.CancelledError:
                            pass

                # Handle the new connection
                if self.connected_protocol == Protocol.CLASSIC:
                    await self._handle_classic_connection()
                    log.success(f"\n[CLASSIC] Receiving HID reports. Press Ctrl+C to exit.")
                    # Loop will continue to wait for next disconnection
                else:
                    break  # Unexpected state
            else:
                # Normal disconnection or max retries reached
                if auth_retry_count >= max_auth_retries:
                    log.error(f"[Classic] Max auth retries ({max_auth_retries}) reached, giving up")
                break

    # ==================== CLASSIC HANDLER ====================

    async def _run_classic_handler(self):
        """Handle Classic Bluetooth connections."""
        # Create HID Host for L2CAP
        self.hid_host = HIDHost(self.device)
        self.hid_host.on(HIDHost.EVENT_INTERRUPT_DATA, self._on_classic_interrupt_data)
        self.hid_host.on(HIDHost.EVENT_VIRTUAL_CABLE_UNPLUG, self._on_virtual_cable_unplug)
        log.info(f"[Classic] HID Host ready (PSM 0x{HID_CONTROL_PSM:04X}, 0x{HID_INTERRUPT_PSM:04X})")

        # Enable Page Scan
        log.info("[Classic] Enabling Page Scan...")
        await self.device.host.send_command(
            HCI_Write_Scan_Enable_Command(scan_enable=0x02),
            check_result=True
        )

        # Connection handler
        async def on_classic_connection(connection):
            if self._connection_future.done():
                log.info("[Classic] Connection received but another protocol won")
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return

            addr_str = str(connection.peer_address)
            log.info(f"[Classic] Device connected: {self._format_device(addr_str)}")

            # Check if allowed
            if not self._is_classic_allowed(addr_str):
                log.warning(f"[Classic] Rejecting {addr_str} (not allowed)")
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return

            self.connection = connection
            self.current_device_address = addr_str
            self.connected_protocol = Protocol.CLASSIC
            connection.on('disconnection', self._on_disconnection)

            # Register with HID host
            self.hid_host.on_device_connection(connection)

            # Authenticate
            log.info("[Classic] Authenticating...")
            try:
                await asyncio.wait_for(connection.authenticate(), timeout=10.0)
                log.success("[Classic] Authentication complete")
            except Exception as e:
                if "transaction collision" not in str(e).lower():
                    log.warning(f"[Classic] Authentication: {e}")

            # Wait for HID channels
            log.info("[Classic] Waiting for HID channels...")
            for _ in range(30):
                if self.hid_host.l2cap_intr_channel and self.hid_host.l2cap_ctrl_channel:
                    log.success("[Classic] HID channels opened")
                    break
                await asyncio.sleep(0.1)

            # Fallback: connect channels ourselves
            if not self.hid_host.l2cap_ctrl_channel:
                try:
                    await asyncio.wait_for(self.hid_host.connect_control_channel(), timeout=5.0)
                except Exception:
                    pass

            if not self.hid_host.l2cap_intr_channel:
                try:
                    await asyncio.wait_for(self.hid_host.connect_interrupt_channel(), timeout=5.0)
                except Exception:
                    pass

            if not self._connection_future.done():
                self._connection_future.set_result(connection)

        def on_connection_event(connection):
            # Only handle Classic connections here
            if hasattr(connection, 'transport') and connection.transport == BT_BR_EDR_TRANSPORT:
                asyncio.create_task(on_classic_connection(connection))
            elif not hasattr(connection, 'transport'):
                # Assume Classic if no transport attribute (older Bumble)
                asyncio.create_task(on_classic_connection(connection))

        self.device.on('connection', on_connection_event)

        # Active connection loop
        active_addresses = [d.address for d in self.classic_devices if d.address != '*']
        if active_addresses:
            await self._classic_active_connect_loop(active_addresses)

    def _is_classic_allowed(self, addr_str: str) -> bool:
        """Check if Classic address is allowed."""
        norm_addr = addr_str.split('/')[0].upper()

        # Check devices.conf
        for dev in self.classic_devices:
            if dev.address == '*':
                return True
            if dev.address.split('/')[0].upper() == norm_addr:
                return True

        # Check keystore
        if norm_addr in self._keystore_addresses:
            return True

        return False

    async def _classic_active_connect_loop(self, addresses: List[str]):
        """Actively try to connect to Classic devices."""
        log.info(f"[Classic] Active: {len(addresses)} device(s)")
        await asyncio.sleep(self.ACTIVE_DELAY)

        attempt = 0
        while not self._connection_future.done():
            attempt += 1
            for addr in addresses:
                if self._connection_future.done():
                    return

                log.info(f"[Classic] Attempt {attempt}: {self._format_device(addr)}")

                try:
                    target = Address(addr, Address.PUBLIC_DEVICE_ADDRESS)
                    connect_task = asyncio.create_task(
                        self.device.connect(target, transport=BT_BR_EDR_TRANSPORT)
                    )

                    for _ in range(self.ACTIVE_CONNECT_TIMEOUT):
                        if self._connection_future.done():
                            connect_task.cancel()
                            return

                        done, _ = await asyncio.wait([connect_task], timeout=0.5)
                        if done:
                            break

                    if not connect_task.done():
                        log.info(f"[Classic] {addr} timed out")
                        connect_task.cancel()
                        try:
                            await connect_task
                        except asyncio.CancelledError:
                            pass
                        await asyncio.sleep(3.0)
                        continue

                    # Task completed - connection event handler will process it
                    await connect_task

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    if "DISALLOWED" in str(e) or "PENDING" in str(e):
                        log.warning("[Classic] HCI busy, waiting...")
                        await asyncio.sleep(5.0)
                    else:
                        log.info(f"[Classic] Connect failed: {e}")
                        await asyncio.sleep(2.0)

            if not self._connection_future.done():
                await asyncio.sleep(self.ACTIVE_RETRY_INTERVAL)

    async def _handle_classic_connection(self):
        """Finalize Classic connection setup."""
        if not self.hid_host.l2cap_intr_channel:
            raise InvalidStateError("HID interrupt channel not connected")

        # Load or query descriptor
        cache = self.device_cache.load(self.current_device_address)
        if cache and 'report_map' in cache:
            self.report_map = bytes.fromhex(cache['report_map'])
            self.device_name = cache.get('device_name')
            log.success(f"[Classic] Loaded cached descriptor ({len(self.report_map)} bytes)")
        else:
            await self._query_classic_sdp()

        if not self.report_map:
            self.report_map = get_fallback_hid_descriptor()
            log.warning("[Classic] Using fallback descriptor")

        self._create_uhid_device()

    async def _query_classic_sdp(self):
        """Query SDP for HID descriptor."""
        if not self.connection:
            return

        log.info("[Classic] Querying SDP...")
        try:
            sdp_client = SDPClient(self.connection)
            await asyncio.wait_for(sdp_client.connect(), timeout=5.0)

            result = await asyncio.wait_for(
                sdp_client.search_attributes(
                    [BT_HUMAN_INTERFACE_DEVICE_SERVICE],
                    [0x0100, 0x0206]
                ),
                timeout=10.0
            )

            if result:
                for record in result:
                    for attr in record:
                        if hasattr(attr, 'id') and attr.id == 0x0206:
                            self._parse_hid_descriptor_list(attr.value)
                        elif hasattr(attr, 'id') and attr.id == 0x0100:
                            try:
                                name = attr.value.value
                                if isinstance(name, bytes):
                                    name = name.decode('utf-8', errors='replace')
                                self.device_name = str(name)
                            except Exception:
                                pass

            await sdp_client.disconnect()

            if self.report_map:
                self.device_cache.save(self.current_device_address, {
                    'report_map': self.report_map.hex(),
                    'device_name': self.device_name or 'Unknown'
                })
        except Exception as e:
            log.warning(f"[Classic] SDP query failed: {e}")

    def _parse_hid_descriptor_list(self, data_element):
        """Parse HID Descriptor List from SDP."""
        try:
            if hasattr(data_element, 'value'):
                data_element = data_element.value

            if isinstance(data_element, (list, tuple)):
                for descriptor in data_element:
                    if hasattr(descriptor, 'value'):
                        descriptor = descriptor.value

                    if isinstance(descriptor, (list, tuple)) and len(descriptor) >= 2:
                        desc_type = descriptor[0]
                        desc_data = descriptor[1]

                        if hasattr(desc_type, 'value'):
                            desc_type = desc_type.value

                        if desc_type == 0x22:  # Report Descriptor
                            if hasattr(desc_data, 'value'):
                                desc_data = desc_data.value

                            if isinstance(desc_data, bytes):
                                self.report_map = desc_data
                            elif isinstance(desc_data, (list, tuple)):
                                self.report_map = bytes(desc_data)

                            log.success(f"[Classic] Got descriptor: {len(self.report_map)} bytes")
                            return
        except Exception as e:
            log.warning(f"[Classic] Failed to parse descriptor: {e}")

    def _on_classic_interrupt_data(self, pdu: bytes):
        """Handle Classic HID report."""
        if len(pdu) < 1:
            return

        report_data = pdu[1:]

        if report_data != self._last_report:
            log.debug(f"[Classic] Report: {report_data.hex()}")
            self._last_report = report_data

        if self.uhid_device:
            try:
                self.uhid_device.send_input(report_data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _on_virtual_cable_unplug(self):
        """Handle virtual cable unplug."""
        log.warning("[Classic] Virtual cable unplugged")
        self._disconnection_event.set()

    # ==================== BLE HANDLER ====================

    async def _run_ble_handler(self):
        """Handle BLE connections."""
        log.info(f"[BLE] Scanning for {len(self.ble_devices)} device(s)...")

        target_addresses = set()
        for dev in self.ble_devices:
            if dev.address != '*':
                target_addresses.add(dev.address.split('/')[0].upper())

        # Also include keystore addresses for BLE
        # (they might have been paired but not in devices.conf)

        while not self._connection_future.done():
            # Scan for devices
            found_device = None

            def on_advertisement(advertisement):
                nonlocal found_device
                if self._connection_future.done():
                    return

                addr = str(advertisement.address).split('/')[0].upper()
                if addr in target_addresses:
                    found_device = advertisement
                    log.info(f"[BLE] Found target: {addr}")

            self.device.on('advertisement', on_advertisement)

            try:
                await self.device.start_scanning()
                # Scan for a few seconds
                for _ in range(20):  # 10 seconds
                    if found_device or self._connection_future.done():
                        break
                    await asyncio.sleep(0.5)
                await self.device.stop_scanning()
            except Exception as e:
                log.warning(f"[BLE] Scan error: {e}")
            finally:
                self.device.remove_listener('advertisement', on_advertisement)

            if self._connection_future.done():
                return

            if found_device:
                # Connect to found device
                try:
                    log.info(f"[BLE] Connecting to {found_device.address}...")
                    self.connection = await asyncio.wait_for(
                        self.device.connect(found_device.address, own_address_type=OwnAddressType.PUBLIC),
                        timeout=config.connect_timeout
                    )

                    if self._connection_future.done():
                        await self.connection.disconnect()
                        return

                    self.peer = Peer(self.connection)
                    self.current_device_address = str(found_device.address)
                    self.connected_protocol = Protocol.BLE
                    self.connection.on('disconnection', self._on_disconnection)

                    # Authenticate
                    await self._ble_restore_or_pair()

                    if not self._connection_future.done():
                        self._connection_future.set_result(self.connection)
                    return

                except Exception as e:
                    log.warning(f"[BLE] Connect failed: {e}")

            # Wait before next scan
            if not self._connection_future.done():
                await asyncio.sleep(3.0)

    async def _ble_restore_or_pair(self):
        """Restore BLE bonding or initiate new pairing."""
        if self.device.keystore:
            try:
                keys = await self.device.keystore.get(str(self.connection.peer_address))
                if keys:
                    log.info("[BLE] Restoring bonding...")
                    await self.connection.encrypt()
                    log.success("[BLE] Bonding restored")
                    return
            except Exception as e:
                log.warning(f"[BLE] Bonding restore failed: {e}")

        log.info("[BLE] Initiating pairing...")
        await self.connection.pair()
        log.success("[BLE] Pairing complete")

    async def _handle_ble_connection(self):
        """Finalize BLE connection setup."""
        # Load cached descriptor
        cache = self.device_cache.load(self.current_device_address)
        if cache and 'report_map' in cache:
            self.report_map = bytes.fromhex(cache['report_map'])
            self.device_name = cache.get('device_name')
            log.success(f"[BLE] Loaded cached descriptor ({len(self.report_map)} bytes)")

        # Discover GATT services
        await self._discover_ble_hid_service()

        if not self.report_map:
            raise InvalidStateError("[BLE] No report descriptor available")

        self._create_uhid_device()

        # Subscribe to reports
        await self._subscribe_to_ble_reports()

    async def _discover_ble_hid_service(self):
        """Discover BLE GATT HID service."""
        await self.peer.discover_services()

        # Read device name
        if not self.device_name:
            await self._read_ble_device_name()

        hid_services = [s for s in self.peer.services if s.uuid == GATT_HUMAN_INTERFACE_DEVICE_SERVICE]
        if not hid_services:
            raise InvalidStateError("[BLE] HID service not found")

        hid_service = hid_services[0]
        log.success("[BLE] Found HID service")

        await self.peer.discover_characteristics(service=hid_service)

        for char in hid_service.characteristics:
            if char.uuid == GATT_REPORT_MAP_CHARACTERISTIC and not self.report_map:
                try:
                    value = await self.peer.read_value(char)
                    self.report_map = bytes(value)
                    log.success(f"[BLE] Got descriptor: {len(self.report_map)} bytes")

                    self.device_cache.save(self.current_device_address, {
                        'report_map': self.report_map.hex(),
                        'device_name': self.device_name
                    })
                except Exception as e:
                    log.warning(f"[BLE] Failed to read report map: {e}")

            elif char.uuid == GATT_REPORT_CHARACTERISTIC:
                await self._process_ble_report_char(char)

    async def _read_ble_device_name(self):
        """Read BLE device name from Generic Access Service."""
        try:
            for service in self.peer.services:
                if service.uuid == GATT_GENERIC_ACCESS_SERVICE:
                    await self.peer.discover_characteristics(service=service)
                    for char in service.characteristics:
                        if char.uuid == GATT_DEVICE_NAME_CHARACTERISTIC:
                            value = await self.peer.read_value(char)
                            self.device_name = bytes(value).decode('utf-8', errors='replace')
                            log.info(f"[BLE] Device name: {self.device_name}")
                            return
        except Exception as e:
            log.warning(f"[BLE] Could not read device name: {e}")

    async def _process_ble_report_char(self, char):
        """Process a BLE Report characteristic."""
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
            log.info(f"[BLE] Found input report {report_id}")

    async def _subscribe_to_ble_reports(self):
        """Subscribe to BLE HID input report notifications."""
        for report_id, char in self.hid_reports.items():
            try:
                await self.peer.subscribe(char, self._on_ble_hid_report)
                log.success(f"[BLE] Subscribed to report {report_id}")
            except Exception as e:
                log.warning(f"[BLE] Failed to subscribe to report {report_id}: {e}")

    def _on_ble_hid_report(self, value):
        """Handle BLE HID report."""
        data = bytes(value)

        if data != self._last_report:
            log.debug(f"[BLE] Report: {data.hex()}")
            self._last_report = data

        if self.uhid_device:
            try:
                self.uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    # ==================== COMMON ====================

    def _on_disconnection(self, reason):
        """Handle device disconnection."""
        proto = self.connected_protocol.value.upper() if self.connected_protocol else "?"
        log.warning(f"[{proto}] Device disconnected (reason={reason})")

        # Reason 5 = HCI_AUTHENTICATION_FAILURE - likely stale link key
        if reason == 5 and self.current_device_address and proto == "CLASSIC":
            log.info("[Classic] Authentication failure - will clear stale key and retry")
            self._auth_failure_address = self.current_device_address

        self._disconnection_event.set()

    def _create_uhid_device(self):
        """Create UHID virtual device."""
        if not self._uhid_available:
            log.warning("UHID not available")
            return

        if not self.report_map:
            log.warning("No report descriptor for UHID")
            return

        try:
            name = self.device_name or "HID Device"
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
        if self.uhid_device:
            try:
                self.uhid_device.destroy()
            except Exception:
                pass
            self.uhid_device = None

        # Classic cleanup
        if self.hid_host:
            connection_alive = (self.connection is not None and
                               hasattr(self.connection, 'handle') and
                               self.connection.handle is not None)

            if connection_alive:
                if self.hid_host.l2cap_intr_channel:
                    try:
                        await self.hid_host.disconnect_interrupt_channel()
                    except Exception:
                        pass
                if self.hid_host.l2cap_ctrl_channel:
                    try:
                        await self.hid_host.disconnect_control_channel()
                    except Exception:
                        pass
            self.hid_host = None

        # Disconnect
        connection_alive = (self.connection is not None and
                          hasattr(self.connection, 'handle') and
                          self.connection.handle is not None)

        if connection_alive:
            try:
                await self.connection.disconnect()
            except Exception:
                pass
        self.connection = None
        self.peer = None

        if self.transport:
            await self.transport.close()

    async def clear_stale_key(self, address: str) -> bool:
        """Clear a stale link key from the keystore.

        Args:
            address: Device address to clear key for

        Returns:
            True if key was cleared
        """
        if not self.keystore:
            return False

        try:
            norm_addr = address.split('/')[0].upper()
            keys = await self.keystore.get(norm_addr)
            if keys and keys.link_key:
                log.info(f"[Classic] Clearing stale link key for {address}")
                await self.keystore.delete(norm_addr)
                log.success(f"[Classic] Link key cleared for {address}")
                return True
            return False
        except Exception as e:
            log.warning(f"[Classic] Failed to clear link key: {e}")
            return False
