#!/usr/bin/env python3
"""
Kindle HID Passthrough - Daemon

Persistent connection manager for Bluetooth HID devices.
Maintains connection with auto-reconnect.

Uses StateMachine for explicit state tracking.

For use with init scripts / systemd.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import asyncio
import logging
import signal
import sys

sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import config, create_host, create_unified_host, get_configured_protocols
from logging_utils import setup_daemon_logging
from state_machine import HostState
from __init__ import __version__

logger = logging.getLogger(__name__)


class HIDDaemon:
    """Daemon that maintains persistent connection to an HID device.

    Uses the host's StateMachine to track connection state and make
    informed decisions about reconnection.
    """

    def __init__(self):
        self.device_address = None
        self.protocol = None
        self.running = False
        self.host = None
        self.use_unified = False  # True if mixed protocols configured

    def load_device(self) -> bool:
        """Load device(s) from config file."""
        devices = config.get_all_devices()
        if not devices:
            logger.error(f"No devices in {config.devices_config_file}")
            return False

        # Use first device's protocol, but we'll accept any from the list
        self.device_address, self.protocol, name = devices[0]

        # Check if we have mixed protocols
        protocols = get_configured_protocols()
        self.use_unified = len(protocols) > 1

        if self.use_unified:
            proto_names = ', '.join(p.value for p in protocols)
            logger.info(f"Mixed protocols detected ({proto_names}), using unified host")

        if len(devices) == 1 and self.device_address != '*':
            display = f"{name} ({self.device_address})" if name else self.device_address
            logger.info(f"Device: {display} ({self.protocol.value})")
        else:
            logger.info(f"Accepting {len(devices)} device(s):")
            for addr, proto, dev_name in devices:
                display = f"{dev_name} ({addr})" if dev_name else addr
                logger.info(f"  - {display} ({proto.value})")

        return True

    def _on_state_change(self, old_state: HostState, new_state: HostState):
        """Handle host state transitions."""
        logger.debug(f"Host state: {old_state.name} -> {new_state.name}")

    async def run(self):
        """Main daemon loop."""
        self.running = True

        if not self.load_device():
            return

        logger.info(f"HID Daemon v{__version__}")

        while self.running:
            skip_delay = False

            try:
                logger.info("=== Starting connection ===")
                if self.use_unified:
                    self.host = create_unified_host()
                else:
                    self.host = create_host(self.protocol)

                # Register state change listener
                if hasattr(self.host, 'state_machine'):
                    self.host.state_machine.add_listener(self._on_state_change)

                await self.host.run(self.device_address)

            except asyncio.CancelledError:
                logger.info("Cancelled")
                break

            except Exception as e:
                logger.error(f"Error: {e}")

                # Check host state for more context
                if self.host and hasattr(self.host, 'state'):
                    state = self.host.state
                    logger.debug(f"Host state at error: {state.name}")

            finally:
                # Check for auth failure before cleanup
                auth_fail_addr = None
                if self.host and hasattr(self.host, 'get_auth_failure_address'):
                    auth_fail_addr = self.host.get_auth_failure_address()

                if self.host:
                    # Remove state listener before cleanup
                    if hasattr(self.host, 'state_machine'):
                        self.host.state_machine.remove_listener(self._on_state_change)

                    try:
                        await self.host.cleanup()
                    except Exception:
                        pass

                # Handle auth failure - clear stale key and retry immediately
                if auth_fail_addr:
                    logger.info(f"Auth failure detected for {auth_fail_addr}")
                    try:
                        # Create new host just for key cleanup
                        if self.use_unified:
                            temp_host = create_unified_host()
                        else:
                            temp_host = create_host(self.protocol)
                        if hasattr(temp_host, 'clear_stale_key'):
                            await temp_host.clear_stale_key(auth_fail_addr)
                    except Exception as e:
                        logger.warning(f"Failed to clear stale key: {e}")
                    logger.info("Retrying connection immediately...")
                    skip_delay = True

                self.host = None

            if not self.running:
                break

            if not skip_delay:
                logger.info(f"Reconnecting in {config.reconnect_delay}s...")
                await asyncio.sleep(config.reconnect_delay)

        logger.info("Daemon stopped")

    async def stop(self):
        """Stop the daemon."""
        logger.info("Stopping...")
        self.running = False
        if self.host:
            try:
                await self.host.cleanup()
            except Exception:
                pass

    @property
    def host_state(self) -> HostState:
        """Get current host state, or IDLE if no host."""
        if self.host and hasattr(self.host, 'state'):
            return self.host.state
        return HostState.IDLE


async def main():
    setup_daemon_logging(config.log_file)

    daemon = HIDDaemon()
    shutdown = asyncio.Event()

    def on_signal():
        logger.info("Shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, on_signal)

    task = asyncio.create_task(daemon.run())

    await asyncio.wait(
        [task, asyncio.create_task(shutdown.wait())],
        return_when=asyncio.FIRST_COMPLETED
    )

    if shutdown.is_set():
        await daemon.stop()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    logger.info("Daemon stopped")


if __name__ == '__main__':
    asyncio.run(main())
