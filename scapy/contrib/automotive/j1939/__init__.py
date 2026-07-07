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

from scapy.consts import LINUX
from scapy.config import conf
from scapy.error import log_loading

from scapy.contrib.j1939 import (
    J1939SoftSocket,
    NativeJ1939Socket,
)

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
