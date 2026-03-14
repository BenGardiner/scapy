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

Detection Matrix
----------------

The following table shows the probe each technique sends and the CAN
response it expects from an active CA in order to detect it.

+------------+-----------------------------------------+------------------------------------------+
| Technique  | Probe (sent by scanner)                 | Expected response (from ECU)             |
+============+=========================================+==========================================+
| addr_claim | Broadcast Request (PF=0xEA, DA=0xFF)    | Address Claimed (PF=0xEE, DA=0xFF)       |
|            | for PGN 60928 (0xEE00)                  | SA=ECU-SA, 8-byte J1939 NAME payload     |
+------------+-----------------------------------------+------------------------------------------+
| ecu_id     | Broadcast Request (PF=0xEA, DA=0xFF)    | TP.CM BAM (PF=0xEC, DA=0xFF,             |
|            | for PGN 64965 (0xFDC5)                  | ctrl=0x20) announcing PGN 64965          |
+------------+-----------------------------------------+------------------------------------------+
| unicast    | Unicast Request (PF=0xEA, DA=ECU-SA)    | Any CAN frame (extended) whose           |
|            | for PGN 60928, addressed to each DA     | SA equals the probed DA                  |
+------------+-----------------------------------------+------------------------------------------+
| rts_probe  | TP.CM_RTS (PF=0xEC, DA=ECU-SA)          | TP.CM_CTS (ctrl=0x11) **or**             |
|            | sent to each DA                         | TP_Conn_Abort (ctrl=0xFF) from probed DA |
+------------+-----------------------------------------+------------------------------------------+

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
import time
from threading import Event

# Typing imports
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Set,
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
    J1939_PF_ADDRESS_CLAIMED,
    J1939_PF_REQUEST,
    _j1939_can_id,
    _j1939_decode_can_id,
    log_j1939,
)

# --- Scanner constants

#: PGN for ECU Identification Information (J1939-73 §5.7.5)
PGN_ECU_ID = 0xFDC5  # 64965

#: Bitmask for the CAN extended-frame flag (29-bit identifier)
_CAN_EXTENDED_FLAG = 0x4

#: Default priority for request frames sent by the scanner
_SCAN_PRIORITY = 6

#: Scan address range for unicast / RTS sweeps (0x00 – 0xFD inclusive)
_SCAN_ADDR_RANGE = range(0x00, 0xFE)  # 0xFE = null / 0xFF = broadcast

#: All valid CA scan method names
SCAN_METHODS = ("addr_claim", "ecu_id", "unicast", "rts_probe")


def _build_request_payload(pgn):
    # type: (int) -> bytes
    """Encode *pgn* as a 3-byte little-endian payload for a J1939 Request (PF=0xEA) frame."""
    return struct.pack("<I", pgn)[:3]


# --- Pacing helpers

#: Default CAN bitrate for J1939 networks (SAE J1939-11, 250 kbit/s)
_J1939_DEFAULT_BITRATE = 250000  # bit/s

#: Default maximum fraction of bus bandwidth the scanner may consume (5 %)
_J1939_DEFAULT_BUSLOAD = 0.05


def _can_frame_bits(dlc):
    # type: (int) -> int
    """Return the bit count of a CAN extended frame with *dlc* data bytes.

    Uses the fixed-field formula for a 29-bit extended frame (no bit-stuffing
    overhead):

      SOF(1) + base-ID(11) + SRR(1) + IDE(1) + ext-ID(18) + RTR(1) +
      r1(1) + r0(1) + DLC(4) + data(dlc×8) + CRC(15) + CRC-del(1) +
      ACK(1) + ACK-del(1) + EOF(7) + IFS(3) = 67 + dlc×8 bits.

    :param dlc: number of data bytes (0–8)
    :returns: total frame bit count
    """
    return 67 + dlc * 8


def _inter_probe_delay(bitrate, busload, tx_dlc, rx_dlc, sniff_time):
    # type: (int, float, int, int, float) -> float
    """Compute the extra sleep needed after a probe-response cycle.

    Each probe cycle occupies *tx_dlc*-frame bits (outgoing probe) plus
    *rx_dlc*-frame bits (expected response).  The scanner's bandwidth budget
    is ``bitrate × busload`` bits per second.  If the probe-response exchange
    completes in less time than the budget requires, the caller should sleep for
    the returned value before transmitting the next probe.

    :param bitrate: CAN bus bitrate in bit/s (e.g. 250000 for 250 kbit/s)
    :param busload: fraction of bus capacity the scanner may consume
                    (0 < busload ≤ 1.0)
    :param tx_dlc: DLC of the outgoing probe frame (0–8)
    :param rx_dlc: DLC of the expected response frame (0–8)
    :param sniff_time: seconds already spent waiting for the response
    :returns: non-negative seconds to sleep before the next probe
    :raises ValueError: when *busload* is not in (0, 1.0]
    """
    if not 0.0 < busload <= 1.0:
        raise ValueError(
            "busload must be in (0, 1.0]; got {!r}".format(busload))
    bits = _can_frame_bits(tx_dlc) + _can_frame_bits(rx_dlc)
    min_cycle = bits / (bitrate * busload)
    return max(0.0, min_cycle - sniff_time)


# --- Passive scan — background noise detection

def j1939_scan_passive(
    sock,                  # type: SuperSocket
    listen_time=1.0,       # type: float
    stop_event=None,       # type: Optional[Event]
):
    # type: (...) -> Set[int]
    """Passively listen to the bus and return the set of observed source addresses.

    Listens for *listen_time* seconds without sending any probe frames and
    records every source address (SA) seen in an extended CAN frame.  The
    returned set can be passed as the ``noise_ids`` argument to the active
    scan functions so that already-known CAs are not re-probed or re-reported.

    :param sock: raw CAN socket to listen on
    :param listen_time: seconds to collect background traffic
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: set of observed source addresses (integers)
    """
    seen = set()  # type: Set[int]

    def _rx(pkt):
        # type: (CAN) -> None
        if stop_event is not None and stop_event.is_set():
            return
        if not (pkt.flags & _CAN_EXTENDED_FLAG):
            return
        _, _, _, sa = _j1939_decode_can_id(pkt.identifier)
        seen.add(sa)

    sock.sniff(prn=_rx, timeout=listen_time, store=False)
    log_j1939.debug("passive: observed %d SA(s): %s",
                    len(seen), [hex(s) for s in sorted(seen)])
    return seen


# --- Technique 1 – Global Address Claim Request

def j1939_scan_addr_claim(
    sock,                                   # type: SuperSocket
    src_addr=J1939_NULL_ADDRESS,            # type: int
    listen_time=1.0,                        # type: float
    noise_ids=None,                         # type: Optional[Set[int]]
    force=False,                            # type: bool
    stop_event=None,                        # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,         # type: int
    busload=_J1939_DEFAULT_BUSLOAD,         # type: float
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs via a global Request for Address Claimed (PGN 60928).

    Sends a single broadcast Request frame and listens for Address Claimed
    replies.  Every J1939-81-compliant CA must respond.

    :param sock: raw CAN socket to use for sending / sniffing
    :param src_addr: source address to use in the request (default 0xFE)
    :param listen_time: seconds to collect responses after sending
    :param noise_ids: set of source addresses already seen on the bus
                      (from :func:`j1939_scan_passive`).  SAs in this set
                      are suppressed from the results unless *force* is True.
    :param force: if True, report all responding SAs even if they appear in
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000).  Accepted for
                    API uniformity; not used by this broadcast technique.
    :param busload: maximum scanner bus-load fraction (default 0.05).
                    Accepted for API uniformity; not used by this broadcast
                    technique.
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
        if not (pkt.flags & _CAN_EXTENDED_FLAG):
            return
        if stop_event is not None and stop_event.is_set():
            return
        _, pf, _, sa = _j1939_decode_can_id(pkt.identifier)
        if pf == J1939_PF_ADDRESS_CLAIMED and sa not in found:
            if not force and noise_ids is not None and sa in noise_ids:
                log_j1939.debug("addr_claim: suppressing noise SA=0x%02X", sa)
                return
            log_j1939.debug("addr_claim: response from SA=0x%02X", sa)
            found[sa] = pkt

    sock.sniff(prn=_rx, timeout=listen_time, store=False)
    return found


# --- Technique 2 – Global ECU ID Request

def j1939_scan_ecu_id(
    sock,                                   # type: SuperSocket
    src_addr=J1939_NULL_ADDRESS,            # type: int
    listen_time=1.0,                        # type: float
    noise_ids=None,                         # type: Optional[Set[int]]
    force=False,                            # type: bool
    stop_event=None,                        # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,         # type: int
    busload=_J1939_DEFAULT_BUSLOAD,         # type: float
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs via a global Request for ECU Identification (PGN 64965).

    Sends a single broadcast Request frame and listens for BAM announce
    headers whose PGN field matches 64965.

    :param sock: raw CAN socket to use for sending / sniffing
    :param src_addr: source address to use in the request (default 0xFE)
    :param listen_time: seconds to collect responses after sending
    :param noise_ids: set of source addresses to suppress from results
                      (see :func:`j1939_scan_passive`)
    :param force: if True, report all responding SAs even if in *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000).  Accepted for
                    API uniformity; not used by this broadcast technique.
    :param busload: maximum scanner bus-load fraction (default 0.05).
                    Accepted for API uniformity; not used by this broadcast
                    technique.
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST,
                           J1939_GLOBAL_ADDRESS, src_addr)
    payload = _build_request_payload(PGN_ECU_ID)
    sock.send(CAN(identifier=can_id, flags="extended", data=payload))
    log_j1939.debug("ecu_id: broadcast request sent (CAN-ID=0x%08X)", can_id)

    found = {}  # type: Dict[int, CAN]

    def _rx(pkt):
        # type: (CAN) -> None
        if not (pkt.flags & _CAN_EXTENDED_FLAG):
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
        if data[0] == 0x20 and data[5:8] == payload and sa not in found:
            if not force and noise_ids is not None and sa in noise_ids:
                log_j1939.debug("ecu_id: suppressing noise SA=0x%02X", sa)
                return
            log_j1939.debug("ecu_id: BAM from SA=0x%02X", sa)
            found[sa] = pkt

    sock.sniff(prn=_rx, timeout=listen_time, store=False)
    return found


# --- Technique 3 – Unicast Ping Sweep

def j1939_scan_unicast(
    sock,                                   # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,            # type: Iterable[int]
    src_addr=J1939_NULL_ADDRESS,            # type: int
    sniff_time=0.1,                         # type: float
    noise_ids=None,                         # type: Optional[Set[int]]
    force=False,                            # type: bool
    stop_event=None,                        # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,         # type: int
    busload=_J1939_DEFAULT_BUSLOAD,         # type: float
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs by sending unicast Address Claim Requests to each DA.

    For each destination address *da* in *scan_range*, sends a Request for
    Address Claimed (PGN 60928) addressed to *da*.  Any CAN frame whose
    source address equals *da* is counted as a positive response.

    When *noise_ids* is provided (and *force* is False), destination addresses
    that appear in *noise_ids* are skipped entirely — no probe is sent and no
    response is recorded for those addresses.  This prevents re-reporting CAs
    already known from background bus traffic.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus, counting both
    the outgoing probe frame and the expected response frame.

    :param sock: raw CAN socket to use for sending / sniffing
    :param scan_range: iterable of destination addresses to probe
    :param src_addr: source address to use in requests (default 0xFE)
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    found = {}  # type: Dict[int, CAN]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("unicast: skipping noise DA=0x%02X", da)
            continue
        can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST, da, src_addr)
        payload = _build_request_payload(PGN_ADDRESS_CLAIMED)
        sock.send(CAN(identifier=can_id, flags="extended", data=payload))
        log_j1939.debug("unicast: probing DA=0x%02X", da)

        # Capture the loop variable explicitly to avoid closure capture issues
        _da = da

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, _, _, sa = _j1939_decode_can_id(pkt.identifier)
            if sa == _da and _da not in found:
                log_j1939.debug("unicast: response from SA=0x%02X", sa)
                found[_da] = pkt

        sock.sniff(prn=_rx, timeout=sniff_time, store=False)

        # Pace the probe rate: request=3 bytes (DLC 3), response=8 bytes (DLC 8)
        _extra = _inter_probe_delay(bitrate, busload, 3, 8, sniff_time)
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Technique 4 – TP.CM RTS Probing

def j1939_scan_rts_probe(
    sock,                                   # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,            # type: Iterable[int]
    src_addr=J1939_NULL_ADDRESS,            # type: int
    sniff_time=0.1,                         # type: float
    noise_ids=None,                         # type: Optional[Set[int]]
    force=False,                            # type: bool
    stop_event=None,                        # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,         # type: int
    busload=_J1939_DEFAULT_BUSLOAD,         # type: float
):
    # type: (...) -> Dict[int, CAN]
    """Enumerate CAs by sending minimal TP.CM_RTS frames to each DA.

    For each destination address *da* in *scan_range*, sends a TP.CM_RTS
    (Connection Management – Request to Send) frame.  An active node
    replies with either TP.CM_CTS (clear to send) or ``TP_Conn_Abort``
    (connection abort).  Both responses confirm the node is present.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus.

    :param sock: raw CAN socket to use for sending / sniffing
    :param scan_range: iterable of destination addresses to probe
    :param src_addr: source address to use in probes (default 0xFE)
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :returns: dict mapping responder source address (int) to the CAN reply
    """
    found = {}  # type: Dict[int, CAN]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("rts_probe: skipping noise DA=0x%02X", da)
            continue
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
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
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

        # Pace the probe rate: RTS probe=8 bytes (DLC 8), response=8 bytes (DLC 8)
        _extra = _inter_probe_delay(bitrate, busload, 8, 8, sniff_time)
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Top-level combined scanner

def j1939_scan(
    sock,                                   # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,            # type: Iterable[int]
    methods=None,                           # type: Optional[List[str]]
    src_addr=J1939_NULL_ADDRESS,            # type: int
    sniff_time=0.1,                         # type: float
    broadcast_listen_time=1.0,              # type: float
    noise_listen_time=1.0,                  # type: float
    noise_ids=None,                         # type: Optional[Set[int]]
    force=False,                            # type: bool
    stop_event=None,                        # type: Optional[Event]
    verbose=False,                          # type: bool
    bitrate=_J1939_DEFAULT_BITRATE,         # type: int
    busload=_J1939_DEFAULT_BUSLOAD,         # type: float
):
    # type: (...) -> Dict[int, Dict[str, object]]
    """Scan for J1939 Controller Applications using one or more techniques.

    Runs each requested scan method and merges the results.  The returned
    dictionary maps each discovered source address to a dict with keys:

    - ``"method"`` (str): name of the first technique that found this CA
    - ``"packet"`` (CAN): the first CAN response received from this CA

    By default, before running any active probe the function performs a
    passive bus listen (via :func:`j1939_scan_passive`) for *noise_listen_time*
    seconds to detect pre-existing source addresses.  Those addresses are then
    excluded from active probing and from the results.  Pass *force=True* to
    disable this filtering, or supply an explicit *noise_ids* set to bypass the
    passive pre-scan.

    :param sock: raw CAN socket (e.g. a :class:`~scapy.contrib.cansocket.CANSocket`)
    :param scan_range: DA range for unicast / RTS sweeps (default 0x00–0xFD)
    :param methods: list of method names to run; valid values are
                    ``"addr_claim"``, ``"ecu_id"``, ``"unicast"``,
                    ``"rts_probe"``.  Default is all four.
    :param src_addr: source address used in outgoing probes (default 0xFE)
    :param sniff_time: per-address listen time for unicast / RTS methods
    :param broadcast_listen_time: listen time for broadcast methods
    :param noise_listen_time: seconds for the passive pre-scan (default 1.0).
                              Only used when *noise_ids* is None and *force*
                              is False.
    :param noise_ids: explicit set of source addresses to exclude from
                      probing and results.  When provided the passive pre-scan
                      is skipped.
    :param force: if True, disable noise filtering entirely (no passive pre-scan,
                  all addresses are probed and reported)
    :param stop_event: :class:`threading.Event` to abort the scan early
    :param verbose: if True, log discovered CAs to the console
    :param bitrate: CAN bus bitrate in bit/s passed to unicast / RTS methods
                    (default 250000 for J1939)
    :param busload: maximum scanner bus-load fraction passed to unicast / RTS
                    methods (default 0.05 = 5 %)
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

    # Step 0: passive pre-scan to detect background noise unless disabled.
    if not force and noise_ids is None:
        if stop_event is not None and stop_event.is_set():
            return {}
        noise_ids = j1939_scan_passive(
            sock, listen_time=noise_listen_time, stop_event=stop_event)
        if verbose and noise_ids:
            log_j1939.info("j1939_scan: %d noise SA(s) detected, will skip: %s",
                           len(noise_ids), [hex(s) for s in sorted(noise_ids)])

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
            noise_ids=noise_ids,
            force=force,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
        ), "addr_claim")

    if "ecu_id" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_ecu_id(
            sock,
            src_addr=src_addr,
            listen_time=broadcast_listen_time,
            noise_ids=noise_ids,
            force=force,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
        ), "ecu_id")

    if "unicast" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_unicast(
            sock,
            scan_range=scan_range_list,
            src_addr=src_addr,
            sniff_time=sniff_time,
            noise_ids=noise_ids,
            force=force,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
        ), "unicast")

    if "rts_probe" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(j1939_scan_rts_probe(
            sock,
            scan_range=scan_range_list,
            src_addr=src_addr,
            sniff_time=sniff_time,
            noise_ids=noise_ids,
            force=force,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
        ), "rts_probe")

    return results


__all__ = [
    "j1939_scan",
    "j1939_scan_passive",
    "j1939_scan_addr_claim",
    "j1939_scan_ecu_id",
    "j1939_scan_unicast",
    "j1939_scan_rts_probe",
    "PGN_ECU_ID",
    "SCAN_METHODS",
]
