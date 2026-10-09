"""Nonblocking FD I/O for explicitly local AF_UNIX test socketpairs.

Some test sandboxes allow AF_UNIX and read/write but restrict send/shutdown.
These helpers never connect to an IP endpoint.
"""

import asyncio
import os
import socket
from contextlib import contextmanager


async def ready(fd, *, writing):
    loop = asyncio.get_running_loop()
    completed = loop.create_future()

    def wake():
        if not completed.done():
            completed.set_result(None)

    register = loop.add_writer if writing else loop.add_reader
    remove = loop.remove_writer if writing else loop.remove_reader
    register(fd, wake)
    try:
        await completed
    finally:
        remove(fd)


async def sendall(sock, data):
    assert sock.family == socket.AF_UNIX
    view = memoryview(data)
    while view:
        try:
            count = os.write(sock.fileno(), view)
        except BlockingIOError:
            await ready(sock.fileno(), writing=True)
        else:
            view = view[count:]


async def recv(sock, size):
    assert sock.family == socket.AF_UNIX
    while True:
        try:
            return os.read(sock.fileno(), size)
        except BlockingIOError:
            await ready(sock.fileno(), writing=False)


@contextmanager
def local_pair():
    left, right = socket.socketpair()
    left.setblocking(False)
    right.setblocking(False)
    try:
        yield left, right
    finally:
        left.close()
        right.close()


def install_local_io(monkeypatch):
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_sendall", sendall)
    monkeypatch.setattr(loop, "sock_recv", recv)


def run(scenario):
    async def bounded():
        async with asyncio.timeout(10):
            await scenario()

    asyncio.run(bounded())
