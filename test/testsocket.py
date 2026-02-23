# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time
import random

from threading import Lock

from scapy.config import conf
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.error import Scapy_Exception

# Typing imports
from typing import (
    Optional,
    Type,
    Tuple,
    Any,
    List,
)
from scapy.supersocket import SuperSocket

from scapy.plist import (
    PacketList,
    SndRcvList,
)


open_test_sockets = list()  # type: List[TestSocket]


class TestSocket(SuperSocket):

    test_socket_mutex = Lock()

    def __init__(self,
                 basecls=None,  # type: Optional[Type[Packet]]
                 external_obj_pipe=None  # type: Optional[ObjectPipe[bytes]]
                 ):
        # type: (...) -> None
        global open_test_sockets
        self.basecls = basecls
        self.paired_sockets = list()  # type: List[TestSocket]
        self.ins = external_obj_pipe or ObjectPipe(name="TestSocket")  # type: ignore
        self._has_external_obj_pip = external_obj_pipe is not None
        self.outs = None
        open_test_sockets.append(self)

    def __enter__(self):
        # type: () -> TestSocket
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (Optional[Type[BaseException]], Optional[BaseException], Optional[Any]) -> None  # noqa: E501
        """Close the socket"""
        self.close()

    def sr(self, *args, **kargs):
        # type: (Any, Any) -> Tuple[SndRcvList, PacketList]
        """Send and Receive multiple packets
        """
        from scapy import sendrecv
        return sendrecv.sndrcv(self, *args, threaded=False, **kargs)

    def sr1(self, *args, **kargs):
        # type: (Any, Any) -> Optional[Packet]
        """Send one packet and receive one answer
        """
        from scapy import sendrecv
        ans = sendrecv.sndrcv(self, *args, threaded=False, **kargs)[0]  # type: SndRcvList
        if len(ans) > 0:
            pkt = ans[0][1]  # type: Packet
            return pkt
        else:
            return None

    def close(self):
        # type: () -> None
        global open_test_sockets

        if self.closed:
            return

        for s in self.paired_sockets:
            try:
                s.paired_sockets.remove(self)
            except (ValueError, AttributeError, TypeError):
                pass

        if not self._has_external_obj_pip:
            super(TestSocket, self).close()
        else:
            # We don't close external object pipes
            self.closed = True

        try:
            open_test_sockets.remove(self)
        except (ValueError, AttributeError, TypeError):
            pass

    def pair(self, sock):
        # type: (TestSocket) -> None
        self.paired_sockets += [sock]
        sock.paired_sockets += [self]

    def send(self, x):
        # type: (Packet) -> int
        sx = bytes(x)
        for r in self.paired_sockets:
            r.ins.send(sx)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        return len(sx)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return self.basecls, self.ins.recv(0), time.time()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        return select_objects(sockets, remain)


class UnstableSocket(TestSocket):
    """
    This is an unstable socket which randomly fires exceptions or loses
    packets on recv.
    """

    def __init__(self,
                 basecls=None,  # type: Optional[Type[Packet]]
                 external_obj_pipe=None  # type: Optional[ObjectPipe[bytes]]
                 ):
        # type: (...) -> None
        super(UnstableSocket, self).__init__(basecls, external_obj_pipe)
        self.no_error_for_x_rx_pkts = 10
        self.no_error_for_x_tx_pkts = 10

    def send(self, x):
        # type: (Packet) -> int
        if self.no_error_for_x_tx_pkts == 0:
            if random.randint(0, 1000) == 42:
                self.no_error_for_x_tx_pkts = 10
                print("SOCKET CLOSED")
                raise OSError("Socket closed")
        if self.no_error_for_x_tx_pkts > 0:
            self.no_error_for_x_tx_pkts -= 1
        return super(UnstableSocket, self).send(x)

    def recv(self, x=MTU, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        if self.no_error_for_x_tx_pkts == 0:
            if random.randint(0, 1000) == 42:
                self.no_error_for_x_tx_pkts = 10
                raise OSError("Socket closed")
            if random.randint(0, 1000) == 13:
                self.no_error_for_x_tx_pkts = 10
                raise Scapy_Exception("Socket closed")
            if random.randint(0, 1000) == 7:
                self.no_error_for_x_tx_pkts = 10
                raise ValueError("Socket closed")
            if random.randint(0, 1000) == 113:
                self.no_error_for_x_tx_pkts = 10
                return None
        if self.no_error_for_x_tx_pkts > 0:
            self.no_error_for_x_tx_pkts -= 1
        return super(UnstableSocket, self).recv(x, **kwargs)


class SlowTestSocket(TestSocket):
    """A TestSocket that simulates the mux/throttle behavior of
    PythonCANSocket on a slow serial interface (like slcan).

    Frames sent to this socket go into an intermediate serial buffer.
    They only become visible to recv()/select() after mux() moves
    them to the rx ObjectPipe. mux() has a throttle (default 1ms)
    and each frame takes time to read from the serial port (simulated
    by blocking for frame_delay per frame during mux).

    Two filtering modes simulate the before/after fix behavior:

    bus_filters (BUG simulation): Simulates BusABC.recv(timeout=0)
    with can_filters on the raw Bus. Each mux() call reads ONE frame;
    if it doesn't match, it is consumed but NOT delivered, and mux
    returns immediately. This reproduces the real bug where python-can's
    BusABC.recv(timeout=0) returns None after one non-matching frame.

    can_filters (FIX simulation): Simulates the fixed behavior where
    the raw Bus has no filters but mux() applies per-socket filtering
    via _matches_filters(). mux() reads ALL available frames from the
    serial buffer but only delivers matching frames to the ObjectPipe.
    Non-matching frames are consumed and discarded, just like the real
    mux() distributes frames based on each socket's can_filters.
    """

    def __init__(self, basecls=None, frame_delay=0.0002,
                 mux_throttle=0.001, bus_filters=None,
                 can_filters=None):
        # type: (Optional[Type[Packet]], float, float, Optional[List[int]], Optional[List[int]]) -> None
        """
        :param frame_delay: Simulated per-frame serial read time (seconds).
            Default 0.2ms is a fast interface. Use 0.010 (10ms) for
            realistic slcan simulation with continuous background traffic.
        :param mux_throttle: Minimum time between mux calls (default 1ms),
            matching PythonCANSocket's multiplex_rx_packets() throttle.
        :param bus_filters: Optional list of CAN identifiers simulating
            can_filters on the raw Bus (the BUG). When set, mux reads
            ONE frame per call; non-matching frames are consumed but not
            delivered. Mutually exclusive with can_filters.
        :param can_filters: Optional list of CAN identifiers simulating
            per-socket filtering in mux (the FIX). mux reads ALL frames
            but only delivers matching ones. This is how real
            PythonCANSocket works after the fix strips can_filters from
            the raw Bus.
        """
        super(SlowTestSocket, self).__init__(basecls)
        from collections import deque
        self._serial_buffer = deque()  # type: deque[bytes]
        self._serial_lock = Lock()
        self._last_mux = 0.0
        self._frame_delay = frame_delay
        self._mux_throttle = mux_throttle
        self._bus_filters = bus_filters
        self._can_filters = can_filters
        # Replace the ObjectPipe that `ins` refers to with one that
        # intercepts writes and redirects to serial_buffer
        self._real_ins = self.ins
        self.ins = _SlowPipeWrapper(self)

    @staticmethod
    def _extract_can_id(frame):
        # type: (bytes) -> int
        """Extract CAN identifier from raw CAN frame bytes."""
        import struct
        if len(frame) < 4:
            return -1
        return struct.unpack('!I', frame[:4])[0] & 0x1FFFFFFF

    def _mux(self):
        # type: () -> None
        """Move frames from serial buffer to rx ObjectPipe.

        Simulates PythonCANSocket's multiplex_rx_packets() + mux().

        When bus_filters is set (BUG), simulates BusABC.recv(timeout=0)
        with can_filters on the raw Bus: reads ONE frame from serial;
        if it doesn't match, consumed but NOT returned (BusABC returns
        None because timeout=0 expired). Only ~1 frame per mux() call.

        When can_filters is set (FIX), simulates the fixed behavior:
        mux() reads ALL available frames but only delivers matching
        ones to the ObjectPipe. Non-matching frames are consumed and
        discarded. This is how real mux() works after the fix strips
        can_filters from the raw Bus.

        When neither is set, all frames are delivered (no filtering).

        No deadline is used: the loop reads until the serial buffer is
        empty, matching real PythonCANSocket mux() which reads until
        bus.recv(timeout=0) returns None.
        """
        now = time.monotonic()
        if now - self._last_mux < self._mux_throttle:
            return
        while True:
            with self._serial_lock:
                if not self._serial_buffer:
                    break
                frame = self._serial_buffer.popleft()
            if self._frame_delay > 0:
                time.sleep(self._frame_delay)
            # Simulate Bus-level filtering (the BUG)
            if self._bus_filters is not None:
                can_id = self._extract_can_id(frame)
                if can_id not in self._bus_filters:
                    # Frame consumed from serial but NOT delivered.
                    # Simulates BusABC.recv(timeout=0) returning None
                    # after reading one non-matching frame.
                    break
                self._real_ins.send(frame)
                # bus.recv(timeout=0) returns only ONE frame per call
                break
            # Simulate per-socket filtering in mux (the FIX)
            if self._can_filters is not None:
                can_id = self._extract_can_id(frame)
                if can_id not in self._can_filters:
                    # Frame read from serial and discarded by mux's
                    # _matches_filters(). Continue reading next frame.
                    continue
            self._real_ins.send(frame)
        self._last_mux = time.monotonic()

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Read from the rx ObjectPipe (populated by mux via select)."""
        return self.basecls, self._real_ins.recv(0), time.time()

    def send(self, x):
        # type: (Packet) -> int
        """Send with serial write delay to simulate slcan."""
        if self._frame_delay > 0:
            time.sleep(self._frame_delay)
        return super(SlowTestSocket, self).send(x)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        for s in sockets:
            if isinstance(s, SlowTestSocket):
                s._mux()
        return select_objects(sockets, remain)

    def close(self):
        # type: () -> None
        self.ins = self._real_ins
        super(SlowTestSocket, self).close()


class _SlowPipeWrapper:
    """Wrapper that intercepts send() to route into serial buffer."""
    def __init__(self, owner):
        # type: (SlowTestSocket) -> None
        self._owner = owner

    def send(self, data):
        # type: (bytes) -> None
        with self._owner._serial_lock:
            self._owner._serial_buffer.append(data)

    def recv(self, timeout=0):
        # type: (float) -> Optional[bytes]
        return self._owner._real_ins.recv(timeout)

    def fileno(self):
        # type: () -> int
        return self._owner._real_ins.fileno()

    def close(self):
        # type: () -> None
        self._owner._real_ins.close()

    @property
    def closed(self):
        # type: () -> bool
        return self._owner._real_ins.closed


def cleanup_testsockets():
    # type: () -> None
    """
    Helper function to remove TestSocket objects after a test
    """
    count = max(len(open_test_sockets), 1)
    while len(open_test_sockets) and count:
        sock = open_test_sockets[0]
        sock.close()
        count -= 1
