"""Bounded, nonblocking, bidirectional socket -> pipe -> socket forwarding."""

import asyncio
import os
import socket
import sys

from ..errors import PlatformError


def ensure_supported(loop: asyncio.AbstractEventLoop) -> None:
    if sys.platform != "linux" or not hasattr(os, "splice") or not hasattr(os, "pipe2"):
        raise PlatformError("the TCP relay requires Linux os.splice and os.pipe2")
    if not hasattr(loop, "add_reader") or not hasattr(loop, "add_writer"):
        raise PlatformError("the event loop must support file descriptor watchers")


class SpliceRelay:
    """Allocates both pipes before a success reply; does not own either socket."""

    def __init__(
        self,
        left: socket.socket,
        right: socket.socket,
        *,
        byte_budget: int = 256 * 1024,
        call_budget: int = 8,
    ):
        self.loop = asyncio.get_running_loop()
        ensure_supported(self.loop)
        if byte_budget <= 0 or call_budget <= 0:
            raise ValueError("splice budgets must be positive")
        self.byte_budget = byte_budget
        self.call_budget = call_budget
        self._finished = self.loop.create_future()
        self._directions: list[_Direction] = []
        self._closed = False
        self._started = False
        try:
            self._directions.append(_Direction(self, left, right))
            self._directions.append(_Direction(self, right, left))
        except BaseException:
            self.close()
            raise

    async def run(self) -> None:
        if self._started or self._closed:
            raise RuntimeError("relay can only be run once")
        self._started = True
        for direction in self._directions:
            direction.wake()
        try:
            await self._finished
        finally:
            self.close()

    def complete_direction(self) -> None:
        if all(direction.done for direction in self._directions):
            if not self._finished.done():
                self._finished.set_result(None)

    def fail(self, error: Exception) -> None:
        if not self._finished.done():
            self._finished.set_exception(error)
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for direction in self._directions:
            direction.close()
        if not self._finished.done():
            self._finished.cancel()


class _Direction:
    def __init__(self, relay: SpliceRelay, source: socket.socket, sink: socket.socket):
        self.relay = relay
        self.loop = relay.loop
        self.source = source
        self.sink = sink
        self.source_fd = source.fileno()
        self.sink_fd = sink.fileno()
        self.read_fd, self.write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.queued = 0
        self.source_eof = False
        self.done = False
        self.closed = False
        self._reading = False
        self._writing = False
        self._scheduled: asyncio.Handle | None = None

    def _unwatch(self) -> None:
        if self._reading:
            self.loop.remove_reader(self.source_fd)
            self._reading = False
        if self._writing:
            self.loop.remove_writer(self.sink_fd)
            self._writing = False

    def wake(self) -> None:
        if self.closed or self.done or self._scheduled is not None:
            return
        self._unwatch()
        self._scheduled = self.loop.call_soon(self._pump)

    def _pump(self) -> None:
        self._scheduled = None
        if self.closed or self.done:
            return
        self._unwatch()
        calls = moved = 0
        try:
            while calls < self.relay.call_budget and moved < self.relay.byte_budget:
                available = self.relay.byte_budget - moved
                if self.queued:
                    calls += 1
                    try:
                        count = os.splice(
                            self.read_fd,
                            self.sink_fd,
                            min(self.queued, available),
                            flags=os.SPLICE_F_NONBLOCK,
                        )
                    except BlockingIOError:
                        self.loop.add_writer(self.sink_fd, self.wake)
                        self._writing = True
                        return
                    if count == 0:
                        raise BrokenPipeError("pipe stopped draining with pending data")
                    self.queued -= count
                    moved += count
                elif not self.source_eof:
                    calls += 1
                    try:
                        count = os.splice(
                            self.source_fd,
                            self.write_fd,
                            available,
                            flags=os.SPLICE_F_NONBLOCK,
                        )
                    except BlockingIOError:
                        self.loop.add_reader(self.source_fd, self.wake)
                        self._reading = True
                        return
                    if count == 0:
                        self.source_eof = True
                    else:
                        self.queued += count
                        moved += count
                else:
                    # All queued bytes must reach the sink before its write EOF.
                    self.sink.shutdown(socket.SHUT_WR)
                    self.done = True
                    self.relay.complete_direction()
                    return
            self.wake()
        except InterruptedError:
            self.wake()
        except Exception as exc:
            self.relay.fail(exc)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._unwatch()
        if self._scheduled is not None:
            self._scheduled.cancel()
            self._scheduled = None
        os.close(self.read_fd)
        os.close(self.write_fd)
