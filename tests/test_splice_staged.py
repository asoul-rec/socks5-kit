"""Real kernel staging keeps the sole reply reader separate from reverse splice."""

import asyncio
import errno
import os
import socket

import pytest

from socks5_kit import BoundAddress
from socks5_kit._io import read_exact, read_reply
from socks5_kit._linux.splice import SpliceRelay
from socks5_kit.protocol import encode_reply

from .local_io import local_pair, run

pytestmark = pytest.mark.tcp_loopback


async def receive(sock):
    loop = asyncio.get_running_loop()
    data = bytearray()
    while chunk := await loop.sock_recv(sock, 4096):
        data.extend(chunk)
    return bytes(data)


def test_staged_reverse_leaves_reply_and_coalesced_payload_for_exact_reader():
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, sender), local_pair() as (right, responder):
            bound = BoundAddress("returned-bound.example", 4321)
            payload = b"target greeting immediately after SOCKS reply\x00\xff"
            relay = SpliceRelay(left, right)
            try:
                relay.start(forward_only=True)
                await loop.sock_sendall(responder, encode_reply(0, bound) + payload)
                assert await relay.read_handshake(read_reply(right)) == bound
                # No reverse watcher may compete with the exact reply reader.
                with pytest.raises(BlockingIOError):
                    sender.recv(1, socket.MSG_PEEK)
                relay.start_reverse()
                assert await read_exact(sender, len(payload)) == payload
                sender.shutdown(socket.SHUT_WR)
                responder.shutdown(socket.SHUT_WR)
                await relay.wait()
                assert all(direction.closed for direction in relay._directions)
            finally:
                relay.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_staged_forward_backpressure_and_eof_survive_delayed_reverse(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, sender), local_pair() as (right, responder):
            for sock in (left, sender, right, responder):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            payload = bytes(range(256)) * 4096
            response = b"response after receiving every forward byte and EOF\x00\xff"
            original = os.splice
            blocked_write = asyncio.Event()

            def observe(src, dst, count, **kwargs):
                try:
                    return original(src, dst, min(count, 257), **kwargs)
                except BlockingIOError:
                    if dst == right.fileno():
                        blocked_write.set()
                    raise

            monkeypatch.setattr(os, "splice", observe)
            relay = SpliceRelay(left, right, byte_budget=4096, call_budget=3)
            wait_task = None

            async def send():
                await loop.sock_sendall(sender, payload)
                sender.shutdown(socket.SHUT_WR)

            try:
                relay.start(forward_only=True)
                wait_task = asyncio.create_task(relay.wait())
                send_task = asyncio.create_task(send())
                # Holding the remote reader produces actual sink backpressure.
                await blocked_write.wait()
                assert await receive(responder) == payload
                await send_task
                assert relay._directions[0].done
                assert not wait_task.done(), "forward EOF must retain the reverse pipe"
                await loop.sock_sendall(responder, response)
                responder.shutdown(socket.SHUT_WR)
                with pytest.raises(BlockingIOError):
                    sender.recv(1, socket.MSG_PEEK)
                relay.start_reverse()
                assert await receive(sender) == response
                await wait_task
            finally:
                relay.close()
                if wait_task is not None:
                    await asyncio.gather(wait_task, return_exceptions=True)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize("failure", ["splice", "cancel"])
def test_staged_handshake_failure_awaits_reader_and_reclaims_pipes(
    monkeypatch, failure
):
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, sender), local_pair() as (right, _responder):
            entered = asyncio.Event()
            finalized = asyncio.Event()
            original = os.splice

            def fail_forward(src, dst, count, **kwargs):
                if src == left.fileno() and entered.is_set() and failure == "splice":
                    raise OSError(errno.EIO, "injected staged forward failure")
                return original(src, dst, count, **kwargs)

            monkeypatch.setattr(os, "splice", fail_forward)

            async def pending_reply():
                entered.set()
                try:
                    return await read_exact(right, 2)
                finally:
                    finalized.set()

            relay = SpliceRelay(left, right)
            try:
                relay.start(forward_only=True)
                task = asyncio.create_task(relay.read_handshake(pending_reply()))
                await entered.wait()
                if failure == "cancel":
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                else:
                    await loop.sock_sendall(sender, b"wake failing forward splice")
                    with pytest.raises(
                        OSError, match="injected staged forward failure"
                    ):
                        await task
                assert finalized.is_set(), (
                    "return only after cancelling the reply reader"
                )
                assert all(direction.closed for direction in relay._directions)
                assert not any(
                    direction._reading or direction._writing
                    for direction in relay._directions
                )
                # Closed relay pipes do not imply ownership of either caller socket.
                assert left.fileno() >= 0 and right.fileno() >= 0
            finally:
                relay.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
