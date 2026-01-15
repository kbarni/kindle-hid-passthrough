#!/usr/bin/env python3
"""
Kindle HID Passthrough

Userspace Bluetooth HID host with UHID passthrough.
Supports both BLE and Classic Bluetooth HID devices.
Forwards all HID reports to Linux via UHID.

Usage:
    main.py                    # Run normally (connect to configured device)
    main.py --pair             # Interactive pairing mode (scans BLE + Classic)
    main.py --daemon           # Run as daemon with auto-reconnect
    main.py --address XX:XX:XX:XX:XX:XX  # Connect to specific address

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import argparse
import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import config, Protocol, create_host, create_scanner, create_unified_host, get_configured_protocols
from logging_utils import log


async def pair_mode(protocol_filter: Protocol = None, sequential: bool = False):
    """Interactive pairing mode - scan and pair with HID device.

    Args:
        protocol_filter: If set, only show devices of this protocol
        sequential: If True, scan BLE then Classic sequentially
    """
    mode = "sequentially" if sequential else "concurrently"
    if protocol_filter:
        log.info(f"Pairing mode (scanning {protocol_filter.value} {mode})")
    else:
        log.info(f"Pairing mode (scanning BLE + Classic {mode})")

    scanner = create_scanner()

    try:
        await scanner.start()

        log.info("Put your device in pairing mode...")
        devices = []
        while not devices:
            all_devices = await scanner.scan(duration=10.0, concurrent=not sequential)
            if protocol_filter:
                devices = [d for d in all_devices if d.protocol == protocol_filter]
            else:
                devices = all_devices
            if not devices:
                log.warning("No HID devices found. Scanning again...")
                await asyncio.sleep(2)

        print("\nFound devices:")
        for i, dev in enumerate(devices):
            proto_tag = "[BLE]" if dev.protocol == Protocol.BLE else "[Classic]"
            print(f"  {i+1}. {proto_tag} {dev.name} ({dev.address})")

        selected = None
        while True:
            try:
                choice = input("\nSelect device (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    selected = devices[idx]
                    break
                print("Invalid selection")
            except ValueError:
                print("Enter a number")
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled")
                return

        log.info(f"Selected: {selected.name} ({selected.address}) [{selected.protocol.value}]")

    finally:
        await scanner.cleanup()

    host = create_host(selected.protocol)

    try:
        await host.start()
        success = await host.pair_device(selected.address)

        if success:
            log.success(f"Paired with {selected.name}")
            save_device_config(selected.address, selected.protocol, selected.name)

            # Continue into run mode if host supports it
            if hasattr(host, 'continue_after_pairing'):
                log.info("Continuing with paired device...")
                await host.continue_after_pairing()
            else:
                log.success("Saved to devices.conf. Run without --pair to connect.")
        else:
            log.error("Pairing failed")

    finally:
        await host.cleanup()


def save_device_config(address: str, protocol: Protocol, name: str = None):
    """Save device to devices.conf (appends, avoids duplicates).

    Format: ADDRESS PROTOCOL [NAME]
    """
    conf_file = config.devices_config_file
    log.info(f"Saving to: {conf_file}")

    dir_path = os.path.dirname(conf_file)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    addr_norm = address.split('/')[0].upper()

    existing_devices = config.get_all_devices()
    for existing_addr, _, _ in existing_devices:
        if existing_addr.split('/')[0].upper() == addr_norm:
            log.info(f"Device {address} already in devices.conf")
            return

    try:
        if not os.path.exists(conf_file):
            with open(conf_file, 'w') as f:
                f.write("# Device addresses and protocols\n")
                f.write("# Format: ADDRESS PROTOCOL [NAME]\n")

        with open(conf_file, 'a') as f:
            if name:
                f.write(f"{address} {protocol.value} {name}\n")
            else:
                f.write(f"{address} {protocol.value}\n")
        log.info(f"Added: {address} {protocol.value} ({name or 'unnamed'})")
    except Exception as e:
        log.error(f"Failed to save: {e}")


async def run_mode(address: str, protocol: Protocol, use_unified: bool = False):
    """Normal run mode - connect and forward reports."""
    if use_unified:
        log.info(f"Connecting using unified host (BLE + Classic)")
        host = create_unified_host()
    else:
        log.info(f"Connecting to {address} ({protocol.value})")
        host = create_host(protocol)

    try:
        await host.run(address)
    except KeyboardInterrupt:
        log.warning("\nInterrupted")
    except Exception as e:
        log.error(f"Error: {e}")
        raise
    finally:
        await host.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description='Kindle HID Passthrough - Userspace Bluetooth HID host'
    )
    parser.add_argument('--pair', action='store_true',
                        help='Interactive pairing mode (scans BLE + Classic)')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon with auto-reconnect')
    parser.add_argument('--address', type=str,
                        help='Device address (overrides devices.conf)')
    parser.add_argument('--protocol', type=str, choices=['ble', 'classic'],
                        help='Filter by protocol (pairing) or override (run)')
    parser.add_argument('--sequential', action='store_true',
                        help='Scan BLE and Classic sequentially')

    args = parser.parse_args()

    log.info(f"Config base path: {config.base_path}")

    protocol_override = None
    if args.protocol:
        protocol_override = Protocol.CLASSIC if args.protocol == 'classic' else Protocol.BLE

    if args.pair:
        asyncio.run(pair_mode(protocol_override, sequential=args.sequential))
        return

    address = args.address
    protocol = protocol_override or config.protocol

    # Check for mixed protocols
    protocols = get_configured_protocols()
    use_unified = len(protocols) > 1 and not protocol_override

    if use_unified:
        proto_names = ', '.join(p.value for p in protocols)
        log.info(f"Mixed protocols detected ({proto_names}), using unified host")

    if not address:
        device_config = config.get_device_config()
        if device_config:
            address, protocol, name = device_config
            if protocol_override:
                protocol = protocol_override
            display = f"{name} ({address})" if name else address
            log.info(f"Using device from {config.devices_config_file}: {display}")
        else:
            log.error("No device address specified. Use --address or create devices.conf")
            log.info("Run with --pair to set up a new device")
            sys.exit(1)

    if not use_unified:
        log.info(f"Using {protocol.value.upper()} protocol")

    if args.daemon:
        # Use daemon module for proper reconnect handling
        from daemon import main as daemon_main
        asyncio.run(daemon_main())
    else:
        asyncio.run(run_mode(address, protocol, use_unified))


if __name__ == '__main__':
    main()
