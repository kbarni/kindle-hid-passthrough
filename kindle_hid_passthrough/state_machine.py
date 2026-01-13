#!/usr/bin/env python3
"""
State Machine for Bluetooth HID Host

Explicit state management for connection lifecycle.
Replaces implicit asyncio.Event flags with proper state tracking.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import asyncio
from enum import Enum, auto
from typing import Callable, List, Optional, Set, Tuple

from logging_utils import log

__all__ = ['HostState', 'StateMachine']


class HostState(Enum):
    """Connection lifecycle states."""
    IDLE = auto()
    STARTING = auto()
    SCANNING = auto()
    CONNECTING = auto()
    AUTHENTICATING = auto()
    DISCOVERING_SERVICES = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    ERROR = auto()


class StateMachine:
    """Manages host connection state with validated transitions.

    Benefits over asyncio.Event flags:
    - Query current state anytime
    - Invalid transitions are caught and logged
    - State change logging built-in
    - Can wait for specific states with timeout
    """

    # Valid state transitions (from_state, to_state)
    VALID_TRANSITIONS: Set[Tuple[HostState, HostState]] = {
        # Startup
        (HostState.IDLE, HostState.STARTING),
        (HostState.STARTING, HostState.SCANNING),
        (HostState.STARTING, HostState.CONNECTING),
        (HostState.STARTING, HostState.ERROR),

        # Scanning
        (HostState.SCANNING, HostState.IDLE),
        (HostState.SCANNING, HostState.CONNECTING),
        (HostState.SCANNING, HostState.ERROR),

        # Connection establishment
        (HostState.CONNECTING, HostState.AUTHENTICATING),
        (HostState.CONNECTING, HostState.DISCOVERING_SERVICES),  # BLE skips auth
        (HostState.CONNECTING, HostState.CONNECTED),  # Already bonded
        (HostState.CONNECTING, HostState.ERROR),
        (HostState.CONNECTING, HostState.IDLE),  # Timeout/cancel

        # Authentication
        (HostState.AUTHENTICATING, HostState.DISCOVERING_SERVICES),
        (HostState.AUTHENTICATING, HostState.CONNECTED),  # Cached services
        (HostState.AUTHENTICATING, HostState.ERROR),
        (HostState.AUTHENTICATING, HostState.IDLE),  # Auth failure/disconnect
        (HostState.AUTHENTICATING, HostState.DISCONNECTING),  # Cleanup during auth

        # Service discovery
        (HostState.DISCOVERING_SERVICES, HostState.CONNECTED),
        (HostState.DISCOVERING_SERVICES, HostState.ERROR),
        (HostState.DISCOVERING_SERVICES, HostState.IDLE),  # Pairing complete
        (HostState.DISCOVERING_SERVICES, HostState.DISCONNECTING),  # Cleanup after pairing

        # Connected state
        (HostState.CONNECTED, HostState.DISCONNECTING),
        (HostState.CONNECTED, HostState.IDLE),  # Remote disconnect
        (HostState.CONNECTED, HostState.ERROR),

        # Disconnecting
        (HostState.DISCONNECTING, HostState.IDLE),
        (HostState.DISCONNECTING, HostState.ERROR),

        # Error recovery
        (HostState.ERROR, HostState.IDLE),
        (HostState.ERROR, HostState.STARTING),  # Retry
    }

    def __init__(self):
        self._state = HostState.IDLE
        self._state_changed = asyncio.Event()
        self._listeners: List[Callable[[HostState, HostState], None]] = []
        self._error_reason: Optional[str] = None

    @property
    def state(self) -> HostState:
        """Current state."""
        return self._state

    @property
    def error_reason(self) -> Optional[str]:
        """Reason for last ERROR state, if any."""
        return self._error_reason

    @property
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._state == HostState.CONNECTED

    @property
    def is_idle(self) -> bool:
        """Check if idle (ready to start)."""
        return self._state == HostState.IDLE

    @property
    def is_busy(self) -> bool:
        """Check if in any active state."""
        return self._state not in (HostState.IDLE, HostState.ERROR)

    def add_listener(self, callback: Callable[[HostState, HostState], None]):
        """Add state change listener. Called with (old_state, new_state)."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[HostState, HostState], None]):
        """Remove state change listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def transition(self, new_state: HostState, reason: Optional[str] = None) -> bool:
        """Attempt state transition.

        Args:
            new_state: Target state
            reason: Optional reason (used for ERROR state)

        Returns:
            True if transition was valid and executed
        """
        if self._state == new_state:
            return True  # No-op, already in this state

        if (self._state, new_state) not in self.VALID_TRANSITIONS:
            log.warning(f"Invalid state transition: {self._state.name} -> {new_state.name}")
            return False

        old_state = self._state
        self._state = new_state

        if new_state == HostState.ERROR:
            self._error_reason = reason
            log.debug(f"State: {old_state.name} -> {new_state.name} ({reason})")
        else:
            self._error_reason = None
            log.debug(f"State: {old_state.name} -> {new_state.name}")

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                log.warning(f"State listener error: {e}")

        # Signal waiters
        self._state_changed.set()
        self._state_changed.clear()

        return True

    def reset(self):
        """Reset to IDLE state (unconditional)."""
        old_state = self._state
        self._state = HostState.IDLE
        self._error_reason = None

        if old_state != HostState.IDLE:
            log.debug(f"State: {old_state.name} -> IDLE (reset)")
            self._state_changed.set()
            self._state_changed.clear()

    async def wait_for(
        self,
        *states: HostState,
        timeout: Optional[float] = None
    ) -> HostState:
        """Wait until state is one of the given states.

        Args:
            *states: Target states to wait for
            timeout: Maximum wait time in seconds

        Returns:
            The state that was reached

        Raises:
            asyncio.TimeoutError: If timeout expires before reaching target state
        """
        if self._state in states:
            return self._state

        deadline = None
        if timeout is not None:
            deadline = asyncio.get_event_loop().time() + timeout

        while self._state not in states:
            remaining = None
            if deadline is not None:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError(
                        f"Timeout waiting for states {[s.name for s in states]}, "
                        f"current: {self._state.name}"
                    )

            try:
                await asyncio.wait_for(
                    self._state_changed.wait(),
                    timeout=remaining
                )
            except asyncio.TimeoutError:
                raise asyncio.TimeoutError(
                    f"Timeout waiting for states {[s.name for s in states]}, "
                    f"current: {self._state.name}"
                )

        return self._state

    async def wait_for_not(
        self,
        *states: HostState,
        timeout: Optional[float] = None
    ) -> HostState:
        """Wait until state is NOT one of the given states.

        Useful for waiting until a transient state completes.

        Args:
            *states: States to wait to leave
            timeout: Maximum wait time in seconds

        Returns:
            The new state after leaving the specified states
        """
        if self._state not in states:
            return self._state

        deadline = None
        if timeout is not None:
            deadline = asyncio.get_event_loop().time() + timeout

        while self._state in states:
            remaining = None
            if deadline is not None:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError(
                        f"Timeout waiting to leave states {[s.name for s in states]}, "
                        f"current: {self._state.name}"
                    )

            try:
                await asyncio.wait_for(
                    self._state_changed.wait(),
                    timeout=remaining
                )
            except asyncio.TimeoutError:
                raise asyncio.TimeoutError(
                    f"Timeout waiting to leave states {[s.name for s in states]}, "
                    f"current: {self._state.name}"
                )

        return self._state

    def __repr__(self) -> str:
        if self._error_reason:
            return f"StateMachine(state={self._state.name}, error={self._error_reason})"
        return f"StateMachine(state={self._state.name})"
