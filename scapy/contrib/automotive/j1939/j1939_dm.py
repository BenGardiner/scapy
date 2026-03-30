# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 Diagnostic Messages (J1939-73)
# scapy.contrib.status = loads

"""
J1939 Diagnostic Messages (DMs) for Scapy.

Implements Scapy packet classes for the most common SAE J1939-73 Diagnostic
Messages, following the same conventions as
:mod:`scapy.contrib.automotive.uds`:

- ``J1939_DTC``  -- 4-byte Diagnostic Trouble Code (SPN / FMI / CM / OC)
- ``J1939_DM1``  -- Active DTCs, PGN 0xFECA (65226)
- ``J1939_DM2``  -- Previously Active DTCs, PGN 0xFECB (65227)
- ``J1939_DM13`` -- Stop/Start Broadcast, PGN 0xE000 (57344)
- ``J1939_DM14`` -- Memory Access Request, PGN 0xD900 (55552)
- ``J1939_DM15`` -- Memory Access Response, PGN 0xD800 (55296)
- ``J1939_NACK`` -- Negative Acknowledgment on PGN 0xE800

All J1939 payload bytes are in little-endian (LE) byte order.  The
``J1939_DTC`` class performs a 4-byte reversal in ``do_dissect`` /
``do_build`` so that Scapy's big-endian ``BitField`` machinery can parse
the LE wire format transparently.

Usage example::

    >>> load_contrib('automotive.j1939')
    >>> from scapy.contrib.automotive.j1939.j1939_dm import (
    ...     J1939_DTC, J1939_DM1, J1939_DM13, J1939_DM14, PGN_DM1
    ... )
    >>> dtc = J1939_DTC(SPN=100, FMI=2, CM=0, OC=5)
    >>> dm1 = J1939_DM1(mil_status=1, dtcs=[dtc])
    >>> len(bytes(dm1))  # padded to 8 bytes
    8
"""

# Typing imports
from typing import (
    Any,
    List,
    Tuple,
)

from scapy.error import Scapy_Exception
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    StrFixedLenField,
    XByteField,
    XLEIntField,
    XShortField,
)
from scapy.packet import Packet

from scapy.contrib.automotive.j1939.j1939_soft_socket import (
    J1939,
    J1939_GLOBAL_ADDRESS,
)

# ---------------------------------------------------------------------------
# PGN constants for Diagnostic Messages (J1939-73)
# ---------------------------------------------------------------------------

#: PGN for DM1 Active Diagnostic Trouble Codes
PGN_DM1 = 0xFECA  # 65226

#: PGN for DM2 Previously Active Diagnostic Trouble Codes
PGN_DM2 = 0xFECB  # 65227

#: PGN for DM13 Stop/Start Broadcast Command
PGN_DM13 = 0xE000  # 57344

#: PGN for DM14 Memory Access Request
PGN_DM14 = 0xD900  # 55552

#: PGN for DM15 Memory Access Response
PGN_DM15 = 0xD800  # 55296

#: PGN for Acknowledgment (including NACK)
PGN_ACK = 0xE800  # 59392

# ---------------------------------------------------------------------------
# FMI descriptions (SAE J1939-73, Table B1)
# ---------------------------------------------------------------------------

#: Failure Mode Indicator descriptions from SAE J1939-73 Table B1.
#: Customize per OEM by updating this dictionary at runtime, matching the
#: ``DTC.dtc_descriptions`` pattern in :mod:`scapy.contrib.automotive.uds`.
FMI_DESCRIPTIONS = {
    0: "DataValidAboveNormalMostSevere",
    1: "DataValidBelowNormalMostSevere",
    2: "DataErratic",
    3: "VoltageAboveNormal",
    4: "VoltageBelowNormal",
    5: "CurrentBelowNormal",
    6: "CurrentAboveNormal",
    7: "MechanicalSystemNotResponding",
    8: "AbnormalFrequencyOrPulseWidth",
    9: "AbnormalUpdateRate",
    10: "AbnormalRateOfChange",
    11: "RootCauseNotKnown",
    12: "BadIntelligentDevice",
    13: "OutOfCalibration",
    14: "SpecialInstructions",
    15: "DataValidAboveNormalLeastSevere",
    16: "DataValidAboveNormalModSevere",
    17: "DataValidBelowNormalLeastSevere",
    18: "DataValidBelowNormalModSevere",
    19: "ReceivedNetworkDataInError",
    20: "ConditionExists",
    21: "DataDrifted",
    31: "NotAvailable",
}

#: SPN descriptions.  Empty by default -- customize per OEM, matching the
#: ``DTC.dtc_descriptions`` pattern in :mod:`scapy.contrib.automotive.uds`.
SPN_DESCRIPTIONS = {}  # type: dict

# ---------------------------------------------------------------------------
# Lamp status encoding (2-bit values per lamp)
# ---------------------------------------------------------------------------

_LAMP_STATUS = {
    0b00: "off",
    0b01: "on",
    0b10: "reserved",
    0b11: "notAvailable",
}

# ---------------------------------------------------------------------------
# DM14 / DM15 command and pointer type encodings
# ---------------------------------------------------------------------------

#: DM14 command type encoding.
DM14_COMMANDS = {
    0: "erase",
    1: "read",
    2: "write",
    3: "reserved",
}

#: DM14/DM15 pointer type encoding.
DM14_POINTER_TYPES = {
    0: "direct",
    1: "indirect",
    2: "copy",
    3: "reserved",
}

#: DM15 status encoding (response to DM14).
DM15_STATUS = {
    0: "proceed",
    1: "busy",
    2: "completed",
    3: "error",
}

# ---------------------------------------------------------------------------
# ACK control byte values (PGN 0xE800)
# ---------------------------------------------------------------------------

#: Acknowledgment control byte values from SAE J1939-21, Table 3.
ACK_CONTROL = {
    0x00: "positiveAcknowledgment",
    0x01: "negativeAcknowledgment",
    0x02: "accessDenied",
    0x03: "cannotRespond",
}


# ###########################DTC####################################
class J1939_DTC(Packet):
    """J1939-73 Diagnostic Trouble Code (4 bytes, little-endian).

    A DTC is a 32-bit little-endian integer with the following bit layout
    (matching the ``DTC`` class in :mod:`scapy.contrib.automotive.uds`):

    - bits 18-0:  SPN (Suspect Parameter Number, 19 bits)
    - bits 23-19: FMI (Failure Mode Indicator, 5 bits)
    - bit  24:    CM  (SPN Conversion Method, 1 bit)
    - bits 31-25: OC  (Occurrence Count, 7 bits)

    Wire bytes (LSB first)::

        byte 0: SPN[7:0]
        byte 1: SPN[15:8]
        byte 2: FMI[4:0] | SPN[18:16]   (bits 7-3 = FMI, bits 2-0 = SPN MSBs)
        byte 3: OC[6:0]  | CM             (bits 7-1 = OC,  bit 0  = CM)

    :param SPN: Suspect Parameter Number (0-524287)
    :param FMI: Failure Mode Indicator (0-31)
    :param CM:  SPN Conversion Method (0-1)
    :param OC:  Occurrence Count (0-127)
    """

    name = "DiagnosticTroubleCode"

    #: SPN descriptions -- customize per OEM at runtime::
    #:
    #:     J1939_DTC.spn_descriptions[100] = "EngineOilPressure"
    spn_descriptions = SPN_DESCRIPTIONS

    #: FMI descriptions from SAE J1939-73 Table B1.
    fmi_descriptions = FMI_DESCRIPTIONS

    fields_desc = [
        # Declared in big-endian (MSB-first) order for BitField processing.
        # do_dissect / do_build reverse the 4 bytes to convert between
        # J1939 little-endian wire format and Scapy's big-endian BitField.
        BitField("OC", 0, 7),  # bits 31-25 (MSB side)
        BitField("CM", 0, 1),  # bit  24
        BitEnumField("FMI", 0, 5, FMI_DESCRIPTIONS),  # bits 23-19
        BitField("SPN", 0, 19),  # bits 18-0  (LSB side)
    ]

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        """Dissect a 4-byte LE DTC from *s*; return remaining bytes."""
        if len(s) >= 4:
            # J1939 DTC is a LE 32-bit word; reverse bytes so that
            # Scapy's BE BitField machinery sees the MSB first.
            super(J1939_DTC, self).do_dissect(s[:4][::-1])
            return s[4:]
        return b""

    def do_build(self):
        # type: () -> bytes
        """Build 4 LE bytes from the current field values."""
        # BitField builds in BE order; reverse to produce J1939 LE wire bytes.
        return super(J1939_DTC, self).do_build()[::-1]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        """No sub-layer payload; all remaining bytes returned as padding."""
        return b"", s


# ###########################DM1####################################
class J1939_DM1(Packet):
    """DM1 Active Diagnostic Trouble Codes (PGN 0xFECA = 65226).

    Wire format:

    - Bytes 0-1: Lamp Status (4 lamps × 2 bits on/off + 4 lamps × 2 bits
      flash pattern).
    - Bytes 2+:  Variable list of :class:`J1939_DTC` records (4 bytes each).

    Single-frame DM1 messages (up to 8 bytes) are zero-padded with ``0xFF``
    to exactly 8 bytes.  Multi-packet messages (>8 bytes) are sent via the
    J1939-21 Transport Protocol, handled automatically by
    :class:`J1939SoftSocket`.

    :param mil_status: Malfunction Indicator Lamp on/off (0=off, 1=on, 3=N/A)
    :param rsl_status: Red Stop Lamp on/off
    :param awl_status: Amber Warning Lamp on/off
    :param pl_status:  Protect Lamp on/off
    :param mil_flash:  MIL flash pattern
    :param rsl_flash:  RSL flash pattern
    :param awl_flash:  AWL flash pattern
    :param pl_flash:   PL flash pattern
    :param dtcs:       list of :class:`J1939_DTC` objects
    """

    name = "ActiveDiagnosticTroubleCodes"

    #: PGN for DM1 Active DTCs (J1939-73)
    PGN = PGN_DM1

    __slots__ = Packet.__slots__ + ["dtcs"]

    fields_desc = [
        # Byte 0: Lamp on/off status
        BitEnumField("mil_status", 3, 2, _LAMP_STATUS),
        BitEnumField("rsl_status", 3, 2, _LAMP_STATUS),
        BitEnumField("awl_status", 3, 2, _LAMP_STATUS),
        BitEnumField("pl_status", 3, 2, _LAMP_STATUS),
        # Byte 1: Lamp flash patterns
        BitEnumField("mil_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("rsl_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("awl_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("pl_flash", 3, 2, _LAMP_STATUS),
    ]

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        self.dtcs = kwargs.pop("dtcs", [])  # type: List[J1939_DTC]
        Packet.__init__(self, *args, **kwargs)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        """Parse 2-byte lamp status then consume 4-byte DTC records."""
        remain = super(J1939_DM1, self).do_dissect(s)
        # Trailing bytes shorter than a full DTC (< 4 bytes) are treated as
        # 0xFF padding and silently ignored, per J1939-21 single-frame rules.
        self.dtcs = []
        while len(remain) >= 4:
            self.dtcs.append(J1939_DTC(remain[:4]))
            remain = remain[4:]
        return b""

    def do_build(self):
        # type: () -> bytes
        """Build lamp status bytes + DTC bytes, padded to 8 bytes if needed."""
        lamp_bytes = super(J1939_DM1, self).do_build()
        dtc_bytes = b"".join(bytes(dtc) for dtc in self.dtcs)
        result = lamp_bytes + dtc_bytes
        if len(result) < 8:
            result += b"\xff" * (8 - len(result))
        return result

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> bool
        """DM1 does not answer any request (it is a broadcast)."""
        return False

    def __repr__(self):
        # type: () -> str
        return (
            "<J1939_DM1 mil_status={} rsl_status={} awl_status={} "
            "pl_status={} dtcs={}>".format(
                self.mil_status,
                self.rsl_status,
                self.awl_status,
                self.pl_status,
                self.dtcs,
            )
        )


# ###########################DM2####################################
class J1939_DM2(Packet):
    """DM2 Previously Active Diagnostic Trouble Codes (PGN 0xFECB = 65227).

    Identical wire format to :class:`J1939_DM1`.  Sent on request via
    PGN 59904 (Request PGN) with the DM2 PGN.

    :param mil_status: Malfunction Indicator Lamp on/off (0=off, 1=on, 3=N/A)
    :param rsl_status: Red Stop Lamp on/off
    :param awl_status: Amber Warning Lamp on/off
    :param pl_status:  Protect Lamp on/off
    :param mil_flash:  MIL flash pattern
    :param rsl_flash:  RSL flash pattern
    :param awl_flash:  AWL flash pattern
    :param pl_flash:   PL flash pattern
    :param dtcs:       list of :class:`J1939_DTC` objects
    """

    name = "PreviouslyActiveDiagnosticTroubleCodes"

    #: PGN for DM2 Previously Active DTCs (J1939-73)
    PGN = PGN_DM2

    __slots__ = Packet.__slots__ + ["dtcs"]

    fields_desc = J1939_DM1.fields_desc[:]

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        self.dtcs = kwargs.pop("dtcs", [])  # type: List[J1939_DTC]
        Packet.__init__(self, *args, **kwargs)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        """Parse 2-byte lamp status then consume 4-byte DTC records."""
        remain = super(J1939_DM2, self).do_dissect(s)
        self.dtcs = []
        while len(remain) >= 4:
            self.dtcs.append(J1939_DTC(remain[:4]))
            remain = remain[4:]
        return b""

    def do_build(self):
        # type: () -> bytes
        """Build lamp status bytes + DTC bytes, padded to 8 bytes if needed."""
        lamp_bytes = super(J1939_DM2, self).do_build()
        dtc_bytes = b"".join(bytes(dtc) for dtc in self.dtcs)
        result = lamp_bytes + dtc_bytes
        if len(result) < 8:
            result += b"\xff" * (8 - len(result))
        return result

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> bool
        """DM2 does not answer any request (broadcast only)."""
        return False

    def __repr__(self):
        # type: () -> str
        return (
            "<J1939_DM2 mil_status={} rsl_status={} awl_status={} "
            "pl_status={} dtcs={}>".format(
                self.mil_status,
                self.rsl_status,
                self.awl_status,
                self.pl_status,
                self.dtcs,
            )
        )


# ###########################DM13###################################
class J1939_DM13(Packet):
    """DM13 Stop/Start Broadcast Command (PGN 0xE000 = 57344).

    Broadcast to all ECUs on the bus to start or stop periodic diagnostic
    broadcast.  The ``hold_signal`` byte uses the J1939-73 convention:

    - ``0x00`` = stop broadcast for general network
    - ``0x01`` = stop broadcast for network #1
    - ``0xFE`` = resume/start broadcasting
    - ``0xFF`` = don't care / not available

    :param hold_signal: broadcast control byte
    :param data: remaining 7 bytes (optional override; default all 0xFF)
    """

    name = "StopStartBroadcast"

    #: PGN for DM13 Stop/Start Broadcast
    PGN = PGN_DM13

    holdSignalValues = {
        0x00: "stopBroadcast",
        0x01: "stopBroadcastNetwork1",
        0x02: "stopBroadcastNetwork2",
        0x03: "stopBroadcastNetwork3",
        0xFE: "resumeBroadcast",
        0xFF: "notAvailable",
    }

    fields_desc = [
        ByteEnumField("hold_signal", 0xFF, holdSignalValues),
        StrFixedLenField("data", b"\xff" * 7, 7),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> bool
        """DM13 is a broadcast command; it does not answer any request."""
        return False


# ###########################DM14###################################
class J1939_DM14(Packet):
    """DM14 Memory Access Request (PGN 0xD900 = 55552).

    Peer-to-peer request to read, write, or erase ECU memory.  DM14 must
    always be addressed to a specific ECU (not the global broadcast address
    ``0xFF``).

    Wire format (8 bytes):

    - Byte 0: bits 7-6 = reserved (1), bits 5-4 = command, bits 3-2 =
      pointer type, bits 1-0 = access level
    - Bytes 1-4: memory address (32-bit LE)
    - Byte 5:    data length (number of bytes to read/write)
    - Bytes 6-7: reserved (0xFFFF)

    :param command_type: memory operation (0=erase, 1=read, 2=write)
    :param pointer_type: addressing mode (0=direct, 1=indirect, 2=copy)
    :param access_level: security access level (0-3)
    :param address:      32-bit LE memory address
    :param length:       number of bytes to access
    """

    name = "MemoryAccessRequest"

    #: PGN for DM14 Memory Access Request
    PGN = PGN_DM14

    fields_desc = [
        # Byte 0: control fields
        BitField("reserved", 0b11, 2),
        BitEnumField("command_type", 1, 2, DM14_COMMANDS),
        BitEnumField("pointer_type", 0, 2, DM14_POINTER_TYPES),
        BitField("access_level", 0, 2),
        # Bytes 1-4: memory address (little-endian)
        XLEIntField("address", 0),
        # Byte 5: data length
        ByteField("length", 0),
        # Bytes 6-7: reserved
        XShortField("reserved2", 0xFFFF),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s


# ###########################DM15###################################
class J1939_DM15(Packet):
    """DM15 Memory Access Response (PGN 0xD800 = 55296).

    Peer-to-peer response to a :class:`J1939_DM14` memory access request.

    Wire format (8 bytes):

    - Byte 0: bits 7-6 = reserved (1), bits 5-4 = status, bits 3-2 =
      pointer type (echo), bits 1-0 = access level (echo)
    - Bytes 1-4: memory address (echo, 32-bit LE)
    - Byte 5:    data length (echo)
    - Bytes 6-7: reserved (0xFFFF)

    :param status:       response status (0=proceed, 1=busy, 2=completed,
                         3=error)
    :param pointer_type: echo of request pointer type
    :param access_level: echo of request access level
    :param address:      echo of request memory address
    :param length:       echo of request data length
    """

    name = "MemoryAccessResponse"

    #: PGN for DM15 Memory Access Response
    PGN = PGN_DM15

    fields_desc = [
        # Byte 0: control fields
        BitField("reserved", 0b11, 2),
        BitEnumField("status", 0, 2, DM15_STATUS),
        BitEnumField("pointer_type", 0, 2, DM14_POINTER_TYPES),
        BitField("access_level", 0, 2),
        # Bytes 1-4: memory address (little-endian)
        XLEIntField("address", 0),
        # Byte 5: data length
        ByteField("length", 0),
        # Bytes 6-7: reserved
        XShortField("reserved2", 0xFFFF),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> bool
        """DM15 is a positive response to :class:`J1939_DM14`."""
        return (isinstance(other, J1939_DM14)
                and other.address == self.address
                and other.pointer_type == self.pointer_type)


# ###########################NACK###################################
class J1939_NACK(Packet):
    """J1939 Negative Acknowledgment (PGN 0xE800 = 59392).

    ECUs send a NACK on PGN 0xE800 when they receive a request they cannot
    fulfil.  This mirrors the ``UDS_NR`` (NegativeResponse) pattern in
    :mod:`scapy.contrib.automotive.uds`.

    Wire format (8 bytes):

    - Byte 0: control byte (0x00=ACK, 0x01=NACK, 0x02=AccessDenied,
      0x03=CannotRespond)
    - Byte 1: group function (0xFF for global)
    - Bytes 2-4: reserved (0xFF)
    - Bytes 5-7: PGN being NACKed (3-byte LE)

    :param control: acknowledgment control byte
    :param group_function: group function value
    :param pgn_lsb: least significant byte of the NACKed PGN
    :param pgn_mid: middle byte of the NACKed PGN
    :param pgn_msb: most significant byte of the NACKed PGN
    """

    name = "NegativeAcknowledgment"

    #: PGN for Acknowledgment
    PGN = PGN_ACK

    fields_desc = [
        ByteEnumField("control", 0x01, ACK_CONTROL),
        XByteField("group_function", 0xFF),
        XByteField("reserved1", 0xFF),
        XByteField("reserved2", 0xFF),
        XByteField("reserved3", 0xFF),
        # PGN being NACKed (3-byte LE)
        XByteField("pgn_lsb", 0),
        XByteField("pgn_mid", 0),
        XByteField("pgn_msb", 0),
    ]

    @property
    def nacked_pgn(self):
        # type: () -> int
        """Return the 24-bit PGN that was NACKed."""
        return self.pgn_lsb | (self.pgn_mid << 8) | (self.pgn_msb << 16)

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> bool
        """A NACK answers any DM request whose PGN matches ``nacked_pgn``."""
        if isinstance(other, (J1939_DM14,)):
            return self.nacked_pgn == other.PGN
        return False


# ---------------------------------------------------------------------------
# Socket utility functions
# ---------------------------------------------------------------------------


def sniff_dm1(
    interface="can0",  # type: str
    timeout=10,  # type: float
):
    # type: (...) -> List[J1939_DM1]
    """Sniff DM1 Active DTC messages from the J1939 bus.

    Opens a :class:`J1939Socket` filtered to PGN 0xFECA (65226) and sniffs
    for ``timeout`` seconds.  Each received payload is dissected into a
    :class:`J1939_DM1` packet.

    :param interface: CAN interface name (e.g. ``"can0"``)
    :param timeout: sniff duration in seconds
    :returns: list of :class:`J1939_DM1` packets received
    """
    from scapy.sendrecv import sniff
    from scapy.contrib.automotive.j1939 import J1939Socket  # type: ignore[attr-defined]

    with J1939Socket(interface, rx_pgn=PGN_DM1) as sock:
        pkts = sniff(opened_socket=sock, timeout=timeout)
    return [J1939_DM1(p.data) for p in pkts if hasattr(p, "data")]


def send_dm14_request(
    interface,  # type: str
    dest_addr,  # type: int
    memory_address,  # type: int
    length=1,  # type: int
):
    # type: (...) -> None
    """Send a DM14 Memory Access Request to a specific ECU.

    :param interface: CAN interface name (e.g. ``"can0"``)
    :param dest_addr: destination ECU address (must not be
                      :data:`J1939_GLOBAL_ADDRESS`)
    :param memory_address: 32-bit memory address to access
    :param length: number of bytes to read
    :raises Scapy_Exception: if *dest_addr* equals
                             :data:`J1939_GLOBAL_ADDRESS`
    """
    if dest_addr == J1939_GLOBAL_ADDRESS:
        raise Scapy_Exception(
            "DM14 is a peer-to-peer message; "
            "dst_addr must not be the broadcast address (0xFF)"
        )
    from scapy.contrib.automotive.j1939 import J1939Socket  # type: ignore[attr-defined]

    dm14 = J1939_DM14(address=memory_address, length=length)
    pkt = J1939(data=bytes(dm14), pgn=PGN_DM14)
    with J1939Socket(
        interface, src_addr=0xFA, dst_addr=dest_addr, pgn=PGN_DM14
    ) as sock:
        sock.send(pkt)


__all__ = [
    "J1939_DTC",
    "J1939_DM1",
    "J1939_DM2",
    "J1939_DM13",
    "J1939_DM14",
    "J1939_DM15",
    "J1939_NACK",
    "PGN_DM1",
    "PGN_DM2",
    "PGN_DM13",
    "PGN_DM14",
    "PGN_DM15",
    "PGN_ACK",
    "FMI_DESCRIPTIONS",
    "SPN_DESCRIPTIONS",
    "DM14_COMMANDS",
    "DM14_POINTER_TYPES",
    "DM15_STATUS",
    "ACK_CONTROL",
    "sniff_dm1",
    "send_dm14_request",
]
