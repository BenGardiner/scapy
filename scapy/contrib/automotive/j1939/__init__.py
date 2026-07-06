# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 Automotive Scanner and DM Layer
# scapy.contrib.status = loads

"""
J1939 automotive tooling built on top of the base J1939 transport layer.

This package provides:

- Address claiming (J1939-81 Network Management)
- Active/passive bus scanning
- DM1/DM4 Diagnostic Message parsing and scanning

The underlying J1939 transport protocol (BAM/CMDT) and soft socket are
provided by :mod:`scapy.contrib.j1939` (polybassa's implementation).

Usage:
    >>> load_contrib('automotive.j1939')
    >>> with J1939Socket("can0", src_addr=0x11) as s:
    ...     s.send(J1939(data=b"Hello, J1939!", pgn=0xFECA, dst=0xFF))
"""

import socket
from typing import Tuple

from scapy.consts import LINUX
from scapy.config import conf
from scapy.error import log_loading

# ── Re-export from polybassa's base J1939 module ──────────────────────────
from scapy.contrib.j1939 import (  # noqa: F401
    J1939,
    J1939_CAN,
    J1939SoftSocket,
    J1939TPImplementation,
    NativeJ1939Socket,
    J1939_TP_CM_RTS,
    J1939_TP_CM_CTS,
    J1939_TP_CM_ACK,
    J1939_TP_CM_BAM,
    J1939_TP_CM_ABORT,
    J1939_TP_CM,
    J1939_TP_DT,
    j1939_to_can_id,
    can_id_to_j1939,
    pgn_is_pdu1,
    pgn_from_fields,
    dst_from_fields,
    log_j1939,
    J1939_BROADCAST_ADDR,
    J1939_PGN_TP_CM,
    J1939_PGN_TP_DT,
    J1939_TP_CTRL_RTS,
    J1939_TP_CTRL_CTS,
    J1939_TP_CTRL_ACK,
    J1939_TP_CTRL_BAM,
    J1939_TP_CTRL_ABORT,
    J1939_PDU1_MAX_PF,
)

# ── Compatibility constants ───────────────────────────────────────────────
# These names were used in the previous implementation and are needed by
# the scanner and DM modules.

#: Global broadcast address (0xFF)
J1939_GLOBAL_ADDRESS = J1939_BROADCAST_ADDR

#: PDU Format byte for TP.CM (0xEC)
J1939_TP_CM_PF = (J1939_PGN_TP_CM >> 8) & 0xFF  # 0xEC

#: PDU Format byte for TP.DT (0xEB)
J1939_TP_DT_PF = (J1939_PGN_TP_DT >> 8) & 0xFF  # 0xEB

#: Transport Protocol control byte constants (old names)
TP_CM_RTS = J1939_TP_CTRL_RTS  # 0x10
TP_CM_CTS = J1939_TP_CTRL_CTS  # 0x11
TP_CM_EndOfMsgACK = J1939_TP_CTRL_ACK  # 0x13
TP_CM_BAM = J1939_TP_CTRL_BAM  # 0x20
TP_Conn_Abort = J1939_TP_CTRL_ABORT  # 0xFF

#: Address Claimed PGN (J1939-81)
PGN_ADDRESS_CLAIMED = getattr(socket, 'J1939_PGN_ADDRESS_CLAIMED', 0xEE00)

#: Request PGN
PGN_REQUEST = getattr(socket, 'J1939_PGN_REQUEST', 0xEA00)

#: PDU Format byte for Address Claimed
J1939_PF_ADDRESS_CLAIMED = (PGN_ADDRESS_CLAIMED >> 8) & 0xFF  # 0xEE

#: PDU Format byte for Request
J1939_PF_REQUEST = (PGN_REQUEST >> 8) & 0xFF  # 0xEA

#: Null address (address not yet claimed)
J1939_NULL_ADDRESS = 0xFE

#: Address claim timeout (250 ms per J1939-81)
J1939_ADDR_CLAIM_TIMEOUT = 0.250

#: Maximum single-frame payload
J1939_MAX_SF_DLEN = 8

#: Maximum TP payload
J1939_TP_MAX_DLEN = 1785

#: TP DT padding byte
J1939_TP_DT_PAD = 0xFF

#: Max sequence number in TP.DT
J1939_TP_DT_MAX_SN = 255

#: Usable data bytes per TP.DT packet
J1939_TP_DT_PAYLOAD = 7

#: Default J1939 TP priority
J1939_TP_PRIORITY = 7

#: CTS value meaning "no limit on packets per block"
TP_CM_MAX_PACKETS_NO_LIMIT = 0xFF

#: TP DT timeout extension factor
TP_DT_TIMEOUT_EXTENSION_FACTOR = 10

# ── Compatibility wrapper functions ───────────────────────────────────────


def _j1939_can_id(priority, pf, da, sa):
    # type: (int, int, int, int) -> int
    """Build a 29-bit J1939 CAN identifier (simplified 4-param form).

    Wraps :func:`~scapy.contrib.j1939.j1939_to_can_id` with
    reserved=0 and data_page=0.
    """
    return j1939_to_can_id(priority, 0, 0, pf, da, sa)


def _j1939_decode_can_id(can_id):
    # type: (int) -> Tuple[int, int, int, int]
    """Decode a 29-bit J1939 CAN identifier to (priority, pf, ps, sa).

    Wraps :func:`~scapy.contrib.j1939.can_id_to_j1939` returning a tuple.
    """
    d = can_id_to_j1939(can_id)
    return d['priority'], d['pdu_format'], d['pdu_specific'], d['src']


# ── Public socket alias ───────────────────────────────────────────────────
# Use J1939Socket as the user-facing name; maps to soft or native based on
# configuration.

if conf.contribs.get('J1939', {}).get('use-j1939-kernel-module', False):
    if LINUX:
        J1939Socket = NativeJ1939Socket
    else:
        log_loading.info("J1939 kernel module not available on this platform, "
                         "using J1939SoftSocket")
        J1939Socket = J1939SoftSocket  # type: ignore[misc]
else:
    J1939Socket = J1939SoftSocket  # type: ignore[misc]

# ── Import scanner and DM modules ─────────────────────────────────────────
from scapy.contrib.automotive.j1939.j1939_dm import (  # noqa: E402, F401
    J1939_DTC,
    J1939_DM1,
    J1939_DM13,
    J1939_DM14,
    PGN_DM1,
    PGN_DM13,
    PGN_DM14,
    sniff_dm1,
    send_dm14_request,
)
from scapy.contrib.automotive.j1939.j1939_scanner import (  # noqa: E402, F401
    j1939_scan,
    j1939_scan_passive,
    j1939_scan_addr_claim,
    j1939_scan_ecu_id,
    j1939_scan_unicast,
    j1939_scan_rts_probe,
    PGN_ECU_ID,
    SCAN_METHODS,
)
from scapy.contrib.automotive.j1939.j1939_dm_scanner import (  # noqa: E402, F401
    DmScanResult,
    J1939_DM_PGNS,
    J1939_PF_ACK,
    PGN_ACK,
    j1939_scan_dm,
    j1939_scan_dm_pgn,
)
from scapy.contrib.automotive.j1939.j1939_address_claim import (  # noqa: E402, F401
    J1939AddressClaimingSocket,
    J1939AddressClaimingTP,
    J1939_ADDR_STATE_UNCLAIMED,
    J1939_ADDR_STATE_CLAIMING,
    J1939_ADDR_STATE_CLAIMED,
    J1939_ADDR_STATE_CANNOT_CLAIM,
)
