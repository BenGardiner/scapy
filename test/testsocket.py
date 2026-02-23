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

    When bus_filters is set (list of CAN identifiers), simulates
    BusABC.recv(timeout=0) with can_filters on the raw Bus. In this
    mode, each mux() call reads ONE frame from the serial buffer;
    if the frame doesn't match any bus_filter, it is consumed (removed
    from buffer) but NOT delivered, and mux returns immediately. This
    reproduces the real bug where python-can's BusABC.recv(timeout=0)
    consumes non-matching frames and returns None (timeout expired),
    making mux() think the serial buffer is empty.
    """

    def __init__(self, basecls=None, frame_delay=0.0002,
                 mux_throttle=0.001, bus_filters=None):
        # type: (Optional[Type[Packet]], float, float, Optional[List[int]]) -> None
        """
        :param frame_delay: Simulated per-frame serial read time (seconds).
            Default 0.2ms is a fast interface. Use 0.010 (10ms) for
            realistic slcan simulation with continuous background traffic.
        :param mux_throttle: Minimum time between mux calls (default 1ms),
            matching PythonCANSocket's multiplex_rx_packets() throttle.
        :param bus_filters: Optional list of CAN identifiers accepted by
            the simulated Bus. When set, simulates the bug where
            BusABC.recv(timeout=0) with can_filters consumes
            non-matching frames without returning them. Set to None
            (default) to simulate the fixed behavior where the raw Bus
            has no filters and mux() reads all frames.
        """
        super(SlowTestSocket, self).__init__(basecls)
        from collections import deque
        self._serial_buffer = deque()  # type: deque[bytes]
        self._serial_lock = Lock()
        self._last_mux = 0.0
        self._frame_delay = frame_delay
        self._mux_throttle = mux_throttle
        self._bus_filters = bus_filters
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

        When bus_filters is set, simulates the bug where
        BusABC.recv(timeout=0) with can_filters on the raw Bus reads
        ONE frame from serial; if it doesn't match any filter, the
        frame is consumed but NOT returned (BusABC returns None because
        timeout=0 expired). mux() sees None and stops, thinking the
        serial buffer is empty. This means only ~1 frame is consumed
        per mux() call regardless of how many frames are buffered.

        When bus_filters is None (simulating the fix where the raw Bus
        has no filters), mux() reads all available frames and delivers
        them all. Per-socket filtering happens in on_can_recv().
        """
        now = time.monotonic()
        if now - self._last_mux < self._mux_throttle:
            return
        deadline = time.monotonic() + 0.01
        while True:
            with self._serial_lock:
                if not self._serial_buffer:
                    break
                frame = self._serial_buffer.popleft()
            if self._frame_delay > 0:
                time.sleep(self._frame_delay)
            # Simulate Bus-level filtering behavior
            if self._bus_filters is not None:
                can_id = self._extract_can_id(frame)
                if can_id not in self._bus_filters:
                    # Frame consumed from serial but NOT delivered.
                    # Simulates BusABC.recv(timeout=0) returning None
                    # after reading one non-matching frame.
                    break
            self._real_ins.send(frame)
            if self._bus_filters is not None:
                # With bus_filters, simulate bus.recv(timeout=0) returning
                # only ONE matching frame per call
                break
            if time.monotonic() > deadline:
                break
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
