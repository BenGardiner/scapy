# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939-81 Address Claiming Extension
# scapy.contrib.status = library

"""
J1939-81 Network Management — Address Claiming.

Extends polybassa's :class:`~scapy.contrib.j1939.J1939TPImplementation`
to add SAE J1939-81 address claiming support.

When an ECU NAME (64-bit integer) is provided, the socket will:

1. Broadcast an Address Claimed message (PGN 0xEE00) on startup
2. Wait 250 ms for conflicts (J1939-81 §4.2)
3. Handle arbitration (lower NAME wins)
4. Respond to Request PGN (0xEA00) for Address Claimed
5. Block application sends until address is claimed or lost

Reference:
    SAE J1939-81 Network Management specification
"""

import struct
import logging
import socket
import time

from typing import (
    Optional,
    Tuple,
    Type,
    Union,
    cast,
    TYPE_CHECKING,
)

from scapy.packet import Packet
from scapy.layers.can import CAN
from scapy.error import Scapy_Exception
from scapy.consts import LINUX
from scapy.supersocket import SuperSocket

from scapy.contrib.j1939 import (
    J1939,
    J1939_CAN,
    J1939SoftSocket,
    J1939TPImplementation,
    J1939_BROADCAST_ADDR,
    J1939_PGN_TP_CM,
    J1939_PGN_TP_DT,
    j1939_to_can_id,
    can_id_to_j1939,
    log_j1939,
)

if TYPE_CHECKING:
    from scapy.contrib.cansocket import CANSocket

# ── Address claiming constants ────────────────────────────────────────────

#: Global broadcast address (0xFF)
J1939_GLOBAL_ADDRESS = J1939_BROADCAST_ADDR

#: Null (Cannot Claim) address — used as SA when address claiming fails
J1939_NULL_ADDRESS = 0xFE

#: Duration (seconds) of the 250 ms address claim window (J1939-81 §4.2)
J1939_ADDR_CLAIM_TIMEOUT = 0.250

#: Address claiming state constants
J1939_ADDR_STATE_UNCLAIMED = 0  # address claiming not enabled
J1939_ADDR_STATE_CLAIMING = 1  # 250 ms window in progress
J1939_ADDR_STATE_CLAIMED = 2  # address successfully claimed
J1939_ADDR_STATE_CANNOT_CLAIM = 3  # lost arbitration; SA = 0xFE

#: PGN for Address Claimed (J1939-81)
PGN_ADDRESS_CLAIMED = getattr(socket, 'J1939_PGN_ADDRESS_CLAIMED', 0xEE00)

#: PGN for Request
PGN_REQUEST = getattr(socket, 'J1939_PGN_REQUEST', 0xEA00)

#: PDU Format byte for Address Claimed
J1939_PF_ADDRESS_CLAIMED = (PGN_ADDRESS_CLAIMED >> 8) & 0xFF  # 0xEE

#: PDU Format byte for Request
J1939_PF_REQUEST = (PGN_REQUEST >> 8) & 0xFF  # 0xEA


def _j1939_can_id(priority, pf, da, sa):
    # type: (int, int, int, int) -> int
    """Build a 29-bit J1939 CAN identifier (simplified 4-param form)."""
    return j1939_to_can_id(priority, 0, 0, pf, da, sa)


class J1939AddressClaimingTP(J1939TPImplementation):
    """J1939 TP implementation with J1939-81 address claiming.

    Extends :class:`J1939TPImplementation` to intercept Address Claimed
    and Request PGN frames, and to manage address claim state.

    :param can_socket: underlying CAN socket
    :param src_addr: source address
    :param name: 64-bit ECU NAME for J1939-81 address claiming.
                 If None, address claiming is disabled.
    :param preferred_address: preferred SA (0-247); defaults to src_addr
    :param priority: default priority for protocol frames
    :param listen_only: if True, do not send CTS/ACK/ABORT/claims
    :param pgn_filter: PGN filter for recv
    """

    def __init__(
        self,
        can_socket,  # type: "CANSocket"
        src_addr=0x00,  # type: int
        name=None,  # type: Optional[int]
        preferred_address=None,  # type: Optional[int]
        priority=6,  # type: int
        listen_only=False,  # type: bool
        pgn_filter=0,  # type: int
    ):
        # type: (...) -> None
        super(J1939AddressClaimingTP, self).__init__(
            can_socket, src_addr,
            listen_only=listen_only,
            pgn_filter=pgn_filter,
        )

        # J1939-81 address claiming
        self.name = name  # type: Optional[int]
        self.priority = priority
        self.preferred_address = (
            preferred_address if preferred_address is not None else src_addr
        )

        # Address claiming state
        self.address_state = J1939_ADDR_STATE_UNCLAIMED
        self.address_claim_handle = None  # type: Optional[object]

        # Start address claiming if name is provided
        if self.name is not None:
            self.address_state = J1939_ADDR_STATE_CLAIMING
            self._send_address_claimed(self.preferred_address)
            self.address_claim_handle = self._TimeoutScheduler.schedule(
                J1939_ADDR_CLAIM_TIMEOUT, self._address_claim_timer_fired
            )

    def close(self):
        # type: () -> None
        """Close and cancel address claim timer."""
        if self.address_claim_handle is not None:
            try:
                self.address_claim_handle.cancel()
            except Exception:
                pass
            self.address_claim_handle = None
        super(J1939AddressClaimingTP, self).close()

    def on_can_recv(self, pkt):
        # type: (Packet) -> None
        """Override to intercept address claiming frames before TP routing."""
        try:
            j = J1939_CAN(bytes(pkt))
            j.time = getattr(pkt, 'time', None) or time.time()
        except Exception:
            return

        pf = j.pdu_format
        ps = j.pdu_specific
        sa = j.src

        # Check for Address Claimed PGN (PF=0xEE, broadcast)
        if pf == J1939_PF_ADDRESS_CLAIMED:
            data = bytes(j.data)
            self._on_address_claimed(data, sa, ps)
            # Still pass through to parent for rx_queue delivery
            # (in case the application wants to see address claims)

        # Check for Request PGN (PF=0xEA)
        if pf == J1939_PF_REQUEST:
            data = bytes(j.data)
            self._on_request_pgn(data, sa, ps)

        # Delegate to parent's on_can_recv for TP and short-frame handling
        # We need to re-parse in the parent, so call super
        super(J1939AddressClaimingTP, self).on_can_recv(pkt)

    def send(self, msg):
        # type: (J1939) -> None
        """Block sends if address is in CANNOT_CLAIM state."""
        if self.name is not None and self.address_state == J1939_ADDR_STATE_CANNOT_CLAIM:
            log_j1939.warning(
                "Cannot send: address claiming failed (CANNOT_CLAIM state)"
            )
            return
        super(J1939AddressClaimingTP, self).send(msg)

    # ──────────────────────────────────────────────────────────────────────
    # J1939-81 Network Management
    # ──────────────────────────────────────────────────────────────────────

    def _send_address_claimed(self, sa):
        # type: (int) -> None
        """Send an Address Claimed message (PGN 0xEE00) broadcast."""
        if self.name is None:
            return
        can_id = _j1939_can_id(
            self.priority, J1939_PF_ADDRESS_CLAIMED, J1939_GLOBAL_ADDRESS, sa
        )
        data = struct.pack("<Q", self.name)
        log_j1939.debug(
            "Sending Address Claimed from SA=0x%02X NAME=0x%016X", sa, self.name
        )
        self.can_socket.send(
            CAN(identifier=can_id, flags="extended", data=data)
        )

    def _send_cannot_claim(self):
        # type: () -> None
        """Send a Cannot Claim message (PGN 0xEE00 from SA=0xFE)."""
        if self.name is None:
            return
        can_id = _j1939_can_id(
            self.priority,
            J1939_PF_ADDRESS_CLAIMED,
            J1939_GLOBAL_ADDRESS,
            J1939_NULL_ADDRESS,
        )
        data = struct.pack("<Q", self.name)
        log_j1939.warning("Sending Cannot Claim (SA=0xFE) NAME=0x%016X", self.name)
        self.can_socket.send(
            CAN(identifier=can_id, flags="extended", data=data)
        )

    def _address_claim_timer_fired(self):
        # type: () -> None
        """Called 250 ms after the initial claim broadcast."""
        if self.closed:
            return
        if self.address_state == J1939_ADDR_STATE_CLAIMING:
            self.address_state = J1939_ADDR_STATE_CLAIMED
            log_j1939.info(
                "Address 0x%02X claimed successfully", self.preferred_address
            )
        self.address_claim_handle = None

    def _on_address_claimed(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle an incoming Address Claimed / Cannot Claim frame.

        Only acts when the sender's SA matches our preferred address.
        Arbitration rule: lower NAME wins.
        """
        if self.name is None:
            return
        if len(data) < 8:
            return
        if sa == J1939_NULL_ADDRESS:
            return
        if sa != self.preferred_address:
            return
        received_name = struct.unpack("<Q", data[:8])[0]
        if received_name == self.name:
            log_j1939.warning(
                "Address Claimed from SA=0x%02X with identical NAME=0x%016X; "
                "ignoring (configuration error)",
                sa, received_name,
            )
            return
        if self.name < received_name:
            # We win — re-broadcast our claim.
            log_j1939.debug(
                "Address conflict on SA=0x%02X: our NAME=0x%016X < "
                "theirs=0x%016X, re-broadcasting our claim",
                sa, self.name, received_name,
            )
            self._send_address_claimed(self.preferred_address)
        else:
            # We lose — enter Cannot Claim state.
            log_j1939.warning(
                "Address conflict on SA=0x%02X: our NAME=0x%016X > "
                "theirs=0x%016X, cannot claim address",
                sa, self.name, received_name,
            )
            if self.address_claim_handle is not None:
                try:
                    self.address_claim_handle.cancel()
                except Exception:
                    pass
                self.address_claim_handle = None
            self.address_state = J1939_ADDR_STATE_CANNOT_CLAIM
            self._send_cannot_claim()

    def _on_request_pgn(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle an incoming Request message (PGN 0xEA00).

        If the requested PGN is Address Claimed, respond appropriately.
        """
        if self.name is None:
            return
        if len(data) < 3:
            return
        requested_pgn = data[0] | (data[1] << 8) | (data[2] << 16)
        if requested_pgn != PGN_ADDRESS_CLAIMED:
            return
        if self.address_state == J1939_ADDR_STATE_CLAIMED:
            log_j1939.debug(
                "Request for PGN_ADDRESS_CLAIMED from SA=0x%02X; "
                "responding with Address Claimed", sa,
            )
            self._send_address_claimed(self.preferred_address)
        else:
            log_j1939.debug(
                "Request for PGN_ADDRESS_CLAIMED from SA=0x%02X; "
                "responding with Cannot Claim (state=%d)", sa, self.address_state,
            )
            self._send_cannot_claim()


class J1939AddressClaimingSocket(J1939SoftSocket):
    """J1939 soft socket with SAE J1939-81 address claiming support.

    Extends :class:`J1939SoftSocket` with the ``name`` and
    ``preferred_address`` parameters for network management.

    :param can_socket: a CANSocket instance or interface name (Linux only)
    :param src_addr: this node's J1939 source address (0x00–0xFD)
    :param name: 64-bit ECU NAME for J1939-81 address claiming.
                 If None, address claiming is disabled and the socket
                 behaves like a regular J1939SoftSocket.
    :param preferred_address: preferred SA (0-247); defaults to src_addr
    :param priority: default priority for frames
    :param listen_only: if True, never send CTS/ACK/ABORT/claims
    :param pgn: PGN filter for recv (0 = accept all)
    :param basecls: packet class for received messages
    """

    def __init__(
        self,
        can_socket=None,  # type: Optional[Union["CANSocket", str]]
        src_addr=0x00,  # type: int
        name=None,  # type: Optional[int]
        preferred_address=None,  # type: Optional[int]
        priority=6,  # type: int
        listen_only=False,  # type: bool
        pgn=0,  # type: int
        basecls=J1939,  # type: Type[Packet]
    ):
        # type: (...) -> None
        if LINUX and isinstance(can_socket, str):
            from scapy.contrib.cansocket_native import NativeCANSocket
            can_socket = NativeCANSocket(can_socket)
        elif isinstance(can_socket, str):
            raise Scapy_Exception(
                "Provide a CANSocket object instead of an interface name")

        self.src_addr = src_addr
        self.basecls = basecls

        impl = J1939AddressClaimingTP(
            can_socket, src_addr,
            name=name,
            preferred_address=preferred_address,
            priority=priority,
            listen_only=listen_only,
            pgn_filter=pgn,
        )
        self.ins = cast(socket.socket, impl)
        self.outs = cast(socket.socket, impl)
        self.impl = impl

        if basecls is None:
            log_j1939.warning("Provide a basecls")

    @property
    def address_state(self):
        # type: () -> int
        """Current address claiming state."""
        return self.impl.address_state

    @property
    def name(self):
        # type: () -> Optional[int]
        """ECU NAME (64-bit integer) or None if claiming not enabled."""
        return self.impl.name
