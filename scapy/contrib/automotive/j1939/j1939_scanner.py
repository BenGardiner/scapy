# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 Controller Application (CA) Scanner
# scapy.contrib.status = library

"""
J1939 Controller Application (CA) Scanner.

Implements four complementary techniques for enumerating active J1939
Controller Applications (CAs / ECUs) on a CAN bus, modelled after the
Scapy ``isotp_scan`` API.

Technique 1 — Global Address Claim Request
    Broadcasts a single Request (PGN 59904) for the Address Claimed PGN
    (60928).  Every active CA that implements J1939-81 address claiming must
    respond.  Best for networks where all nodes are J1939-81 compliant.

Technique 2 — Global ECU Identification Request
    Broadcasts a single Request (PGN 59904) for the ECU Identification Info
    PGN (64965).  Responding nodes announce their ECU ID via a BAM transfer.
    Identifies nodes that publish an ECU Identification string.

Technique 3 — Unicast Ping Sweep
    Iterates through destination addresses 0x00–0xFD, sending a Request for
    Address Claimed to each.  Nodes that are active reply.  Detects nodes
    even if they do not respond to the broadcast in Technique 1.

Technique 4 — TP.CM RTS Probing
    Iterates through destination addresses 0x00–0xFD, sending a minimal
    TP.CM_RTS frame to each.  Active nodes reply with CTS or Conn_Abort,
    both of which confirm the node is present.

Usage::

    >>> load_contrib('automotive.j1939')
    >>> from scapy.contrib.cansocket import CANSocket
    >>> from scapy.contrib.automotive.j1939.j1939_scanner import j1939_scan
    >>> sock = CANSocket("can0")
    >>> found = j1939_scan(sock, methods=["addr_claim", "unicast"])
    >>> for sa, info in found.items():
    ...     print("SA=0x{:02X}  found_by={}".format(sa, info["method"]))
"""

import struct
from threading import Event

# Typing imports
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
)

from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket

from scapy.contrib.automotive.j1939.j1939_soft_socket import (
    J1939_GLOBAL_ADDRESS,
    J1939_NULL_ADDRESS,
    J1939_TP_CM_PF,
    TP_CM_RTS,
    TP_CM_CTS,
    TP_Conn_Abort,
    PGN_ADDRESS_CLAIMED,
    PGN_REQUEST,
    J1939_PF_ADDRESS_CLAIMED,
    J1939_PF_REQUEST,
    _j1939_can_id,
    _j1939_decode_can_id,
    log_j1939,
)

# ---------------------------------------------------------------------------
# Scanner constants
# ---------------------------------------------------------------------------

#: PGN for ECU Identification Information (J1939-73 §5.7.5)
PGN_ECU_ID = 0xFDC5  # 64965

#: Default priority for request frames sent by the scanner
_SCAN_PRIORITY = 6

#: Scan address range for unicast / RTS sweeps (0x00 – 0xFD inclusive)
_SCAN_ADDR_RANGE = range(0x00, 0xFE)  # 0xFE = null / 0xFF = broadcast

#: All valid CA scan method names
SCAN_METHODS = ("addr_claim", "ecu_id", "unicast", "rts_probe")


def _build_request_payload(pgn):
    # type: (int) -> bytes
    """Encode a PGN as a 3-byte little-endian request payload (PGN_REQUEST)."""
    return struct.pack("<I", pgn)[:3]


# ---------------------------------------------------------------------------
# Technique 1 – Global Address Claim Request
# ---------------------------------------------------------------------------

def j1939_scan_addr_claim(
    sock,                        # type: SuperSocket
    src_addr=J1939_NULL_ADDRESS,  # type: int
    listen_time=1.0,             # type: float
    stop_event=None,             # type: Optional[Event]
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs via a global Request for Address Claimed (PGN 60928).

    Sends a single broadcast Request frame and listens for Address Claimed
    replies.  Every J1939-81-compliant CA must respond.

    :param sock: raw CAN socket to use for sending / sniffing
    :param src_addr: source address to use in the request (default 0xFE)
    :param listen_time: seconds to collect responses after sending
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    # Build the request CAN frame:
    # CAN-ID: prio=6, PF=0xEA (Request), DA=0xFF (global), SA=src_addr
    # Payload: 3-byte LE PGN 60928 (0xEE00)
    can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST,
                           J1939_GLOBAL_ADDRESS, src_addr)
    payload = _build_request_payload(PGN_ADDRESS_CLAIMED)
    sock.send(CAN(identifier=can_id, flags="extended", data=payload))
    log_j1939.debug("addr_claim: broadcast request sent (CAN-ID=0x%08X)", can_id)

    found = {}  # type: Dict[int, CAN]

    def _rx(pkt):
        # type: (CAN) -> None
        if not (pkt.flags & 0x4):
            return
        if stop_event is not None and stop_event.is_set():
            return
        _, pf, _, sa = _j1939_decode_can_id(pkt.identifier)
        if pf == J1939_PF_ADDRESS_CLAIMED and sa not in found:
            log_j1939.debug("addr_claim: response from SA=0x%02X", sa)
            found[sa] = pkt

    sock.sniff(prn=_rx, timeout=listen_time, store=False)
    return found


# ---------------------------------------------------------------------------
# Technique 2 – Global ECU ID Request
# ---------------------------------------------------------------------------

def j1939_scan_ecu_id(
    sock,                        # type: SuperSocket
    src_addr=J1939_NULL_ADDRESS,  # type: int
    listen_time=1.0,             # type: float
    stop_event=None,             # type: Optional[Event]
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs via a global Request for ECU Identification (PGN 64965).

    Sends a single broadcast Request frame and listens for BAM announce
    headers whose PGN field matches 64965.

    :param sock: raw CAN socket to use for sending / sniffing
    :param src_addr: source address to use in the request (default 0xFE)
    :param listen_time: seconds to collect responses after sending
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST,
                           J1939_GLOBAL_ADDRESS, src_addr)
    payload = _build_request_payload(PGN_ECU_ID)
    sock.send(CAN(identifier=can_id, flags="extended", data=payload))
    log_j1939.debug("ecu_id: broadcast request sent (CAN-ID=0x%08X)", can_id)

    # The 3-byte LE encoding of PGN 64965 (0xFDC5)
    _ecu_pgn_le = _build_request_payload(PGN_ECU_ID)

    found = {}  # type: Dict[int, CAN]

    def _rx(pkt):
        # type: (CAN) -> None
        if not (pkt.flags & 0x4):
            return
        if stop_event is not None and stop_event.is_set():
            return
        _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
        # We expect a BAM header (TP.CM, DA=0xFF) announcing PGN 64965
        if pf != J1939_TP_CM_PF:
            return
        if ps != J1939_GLOBAL_ADDRESS:
            return
        data = bytes(pkt.data)
        if len(data) < 8:
            return
        # BAM control byte = 0x20, PGN at bytes 5-7 (LE)
        if data[0] == 0x20 and data[5:8] == _ecu_pgn_le and sa not in found:
            log_j1939.debug("ecu_id: BAM from SA=0x%02X", sa)
            found[sa] = pkt

    sock.sniff(prn=_rx, timeout=listen_time, store=False)
    return found


# ---------------------------------------------------------------------------
# Technique 3 – Unicast Ping Sweep
# ---------------------------------------------------------------------------

def j1939_scan_unicast(
    sock,                              # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,       # type: Iterable[int]
    src_addr=J1939_NULL_ADDRESS,       # type: int
    sniff_time=0.1,                    # type: float
    stop_event=None,                   # type: Optional[Event]
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs by sending unicast Address Claim Requests to each DA.

    For each destination address *da* in *scan_range*, sends a Request for
    Address Claimed (PGN 60928) addressed to *da*.  Any CAN frame whose
    source address equals *da* is counted as a positive response.

    :param sock: raw CAN socket to use for sending / sniffing
    :param scan_range: iterable of destination addresses to probe
    :param src_addr: source address to use in requests (default 0xFE)
    :param sniff_time: seconds to wait for a response after each probe
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    found = {}  # type: Dict[int, CAN]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST, da, src_addr)
        payload = _build_request_payload(PGN_ADDRESS_CLAIMED)
        sock.send(CAN(identifier=can_id, flags="extended", data=payload))
        log_j1939.debug("unicast: probing DA=0x%02X", da)

        # Capture the loop variable explicitly to avoid closure capture issues
        _da = da

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & 0x4):
                return
            _, _, _, sa = _j1939_decode_can_id(pkt.identifier)
            if sa == _da and _da not in found:
                log_j1939.debug("unicast: response from SA=0x%02X", sa)
                found[_da] = pkt

        sock.sniff(prn=_rx, timeout=sniff_time, store=False)

    return found


# ---------------------------------------------------------------------------
# Technique 4 – TP.CM RTS Probing
# ---------------------------------------------------------------------------

def j1939_scan_rts_probe(
    sock,                              # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,       # type: Iterable[int]
    src_addr=J1939_NULL_ADDRESS,       # type: int
    sniff_time=0.1,                    # type: float
    stop_event=None,                   # type: Optional[Event]
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs by sending minimal TP.CM_RTS frames to each DA.

    For each destination address *da* in *scan_range*, sends a TP.CM_RTS
    (Connection Management – Request to Send) frame.  An active node
    replies with either TP.CM_CTS (clear to send) or ``TP_Conn_Abort``
    (connection abort).  Both responses confirm the node is present.

    :param sock: raw CAN socket to use for sending / sniffing
    :param scan_range: iterable of destination addresses to probe
    :param src_addr: source address to use in probes (default 0xFE)
    :param sniff_time: seconds to wait for a response after each probe
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: dict mapping responder source address (int) to the CAN reply

    Active nodes reply with either TP.CM_CTS (clear to send) or
    ``TP_Conn_Abort`` (connection abort).  Both responses confirm presence.
    """
    found = {}  # type: Dict[int, CAN]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        # CAN-ID: priority=7, PF=0xEC (TP.CM), DA=da, SA=src_addr
        can_id = _j1939_can_id(7, J1939_TP_CM_PF, da, src_addr)
        # TP.CM_RTS payload (8 bytes):
        #   byte 0: 0x10 = RTS control
        #   bytes 1-2 LE: total message size = 9
        #   byte 3: total packets = 2
        #   byte 4: max packets per CTS = 0xFF (no limit)
        #   bytes 5-7: PGN being transferred (probe PGN = 0x0000FF)
        payload = struct.pack("<BHBBBBB",
                              TP_CM_RTS,  # 0x10
                              9,          # total message size (LE 2-byte)
                              2,          # total number of TP.DT packets
                              0xFF,       # max packets per CTS
                              0xFF,       # PGN byte 1 (probe value)
                              0x00,       # PGN byte 2
                              0x00)       # PGN byte 3
        sock.send(CAN(identifier=can_id, flags="extended", data=payload))
        log_j1939.debug("rts_probe: probing DA=0x%02X", da)

        _da = da

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & 0x4):
                return
            _, pf, _, sa = _j1939_decode_can_id(pkt.identifier)
            if sa != _da or _da in found:
                return
            # TP.CM response from the probed node (CTS or Abort)
            if pf == J1939_TP_CM_PF:
                d = bytes(pkt.data)
                if d and d[0] in (TP_CM_CTS, TP_Conn_Abort):
                    log_j1939.debug(
                        "rts_probe: response (ctrl=0x%02X) from SA=0x%02X",
                        d[0], sa)
                    found[_da] = pkt

        sock.sniff(prn=_rx, timeout=sniff_time, store=False)

    return found


# ---------------------------------------------------------------------------
# Top-level combined scanner
# ---------------------------------------------------------------------------

def j1939_scan(
    sock,                               # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,        # type: Iterable[int]
    methods=None,                       # type: Optional[List[str]]
    src_addr=J1939_NULL_ADDRESS,        # type: int
    sniff_time=0.1,                     # type: float
    broadcast_listen_time=1.0,          # type: float
    stop_event=None,                    # type: Optional[Event]
    verbose=False,                      # type: bool
):
    # type: (...) -> Dict[int, Dict[str, object]]
    """Scan for J1939 Controller Applications using one or more techniques.

    Runs each requested scan method and merges the results.  The returned
    dictionary maps each discovered source address to a dict with keys:

    - ``"method"`` (str): name of the first technique that found this CA
    - ``"packet"`` (CAN): the first CAN response received from this CA

    :param sock: raw CAN socket (e.g. a :class:`~scapy.contrib.cansocket.CANSocket`)
    :param scan_range: DA range for unicast / RTS sweeps (default 0x00–0xFD)
    :param methods: list of method names to run; valid values are
                    ``"addr_claim"``, ``"ecu_id"``, ``"unicast"``,
                    ``"rts_probe"``.  Default is all four.
    :param src_addr: source address used in outgoing probes (default 0xFE)
    :param sniff_time: per-address listen time for unicast / RTS methods
    :param broadcast_listen_time: listen time for broadcast methods
    :param stop_event: :class:`threading.Event` to abort the scan early
    :param verbose: if True, log discovered CAs to the console
    :returns: dict mapping SA (int) to ``{"method": str, "packet": CAN}``

    Example::

        >>> found = j1939_scan(sock)
        >>> for sa, info in sorted(found.items()):
        ...     print("SA=0x{:02X} via {}".format(sa, info["method"]))
    """
    if methods is None:
        methods = list(SCAN_METHODS)

    for m in methods:
        if m not in SCAN_METHODS:
            raise ValueError(
                "Unknown scan method {!r}; valid methods: {}".format(
                    m, SCAN_METHODS))

    results = {}  # type: Dict[int, Dict[str, object]]
    scan_range_list = list(scan_range)

    def _merge(found, method_name):
        # type: (Dict[int, CAN], str) -> None
        for sa, pkt in found.items():
            if sa not in results:
                if verbose:
                    log_j1939.info(
                        "j1939_scan: found SA=0x%02X via %s", sa, method_name)
                results[sa] = {"method": method_name, "packet": pkt}

    if "addr_claim" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_addr_claim(
            sock,
            src_addr=src_addr,
            listen_time=broadcast_listen_time,
            stop_event=stop_event,
        ), "addr_claim")

    if "ecu_id" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_ecu_id(
            sock,
            src_addr=src_addr,
            listen_time=broadcast_listen_time,
            stop_event=stop_event,
        ), "ecu_id")

    if "unicast" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_unicast(
            sock,
            scan_range=scan_range_list,
            src_addr=src_addr,
            sniff_time=sniff_time,
            stop_event=stop_event,
        ), "unicast")

    if "rts_probe" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_rts_probe(
            sock,
            scan_range=scan_range_list,
            src_addr=src_addr,
            sniff_time=sniff_time,
            stop_event=stop_event,
        ), "rts_probe")

    return results


__all__ = [
    "j1939_scan",
    "j1939_scan_addr_claim",
    "j1939_scan_ecu_id",
    "j1939_scan_unicast",
    "j1939_scan_rts_probe",
    "PGN_ECU_ID",
    "SCAN_METHODS",
]
