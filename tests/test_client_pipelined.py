"""The internal staged client streams socket payload before the upstream REP."""

import asyncio
import errno
import os
import socket
from ipaddress import IPv6Address

import pytest

import socks5_kit.client as client_module
from socks5_kit import BoundAddress, Socks5Client, Target, UpstreamRejected
from socks5_kit._io import read_exact
from socks5_kit.protocol import encode_reply

from .local_io import local_pair
from .test_tcp import Service, run, upstream_request

pytestmark = pytest.mark.tcp_loopback


def test_large_payload_and_forward_eof_precede_rep_without_reverse_prefetch():
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        payload = bytes(range(256)) * 8192
        response = b"server speaks immediately after upstream REP\x00\xff"
        bound = BoundAddress(IPv6Address("::1"), 4321)
        received = asyncio.Event()
        release_reply = asyncio.Event()

        async def proxy(reader, writer):
            assert await upstream_request(reader, writer) == BoundAddress(
                "destination.example", 443
            )
            assert await reader.readexactly(len(payload)) == payload
            assert await reader.read() == b""
            received.set()
            await release_reply.wait()
            writer.write(encode_reply(0, bound) + response)
            await writer.drain()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with local_pair() as (source, sender):
                for sock in (source, sender):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

                async def send():
                    await loop.sock_sendall(sender, payload)
                    sender.shutdown(socket.SHUT_WR)

                send_task = asyncio.create_task(send())
                connect_task = asyncio.create_task(
                    client._connect_pipelined(
                        Target("destination.example", 443),
                        source,
                        byte_budget=4096,
                        call_budget=3,
                    )
                )
                await received.wait()
                assert not connect_task.done(), "upstream REP is still withheld"
                await send_task
                release_reply.set()
                tunnel, relay = await connect_task
                try:
                    assert tunnel.bound_address == bound
                    assert relay.byte_budget == 4096 and relay.call_budget == 3
                    assert relay._directions[0].done
                    with pytest.raises(BlockingIOError):
                        sender.recv(1, socket.MSG_PEEK)
                    # A caller's own reply must precede any target application byte.
                    own_reply = b"caller success reply"
                    await loop.sock_sendall(source, own_reply)
                    relay.start_reverse()
                    assert await read_exact(sender, len(own_reply) + len(response)) == (
                        own_reply + response
                    )
                    assert await loop.sock_recv(sender, 1) == b""
                    await relay.wait()
                finally:
                    relay.close()
                    tunnel.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize("failure", ["rejected", "splice", "timeout", "cancel"])
def test_pipelined_failure_reclaims_socket_pipes_and_pending_reply_reader(
    monkeypatch, failure
):
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        entered = asyncio.Event()
        finalized = asyncio.Event()
        closed = asyncio.Event()
        upstream_sock = None
        original_reply = client_module.read_reply
        original_splice = os.splice

        async def tracked_reply(sock):
            nonlocal upstream_sock
            upstream_sock = sock
            entered.set()
            try:
                return await original_reply(sock)
            finally:
                finalized.set()

        monkeypatch.setattr(client_module, "read_reply", tracked_reply)

        async def proxy(reader, writer):
            await upstream_request(reader, writer)
            if failure == "rejected":
                writer.write(b"\x05\x05\x00")
                await writer.drain()
            assert await reader.read() == b""
            closed.set()

        async with Service(proxy) as service:
            client = Socks5Client(
                "127.0.0.1",
                service.port,
                handshake_timeout=0.1 if failure == "timeout" else 10,
            )
            with local_pair() as (source, sender):

                def fail_forward(src, dst, count, **kwargs):
                    if (
                        src == source.fileno()
                        and entered.is_set()
                        and failure == "splice"
                    ):
                        raise OSError(errno.EIO, "injected pipelined splice failure")
                    return original_splice(src, dst, count, **kwargs)

                monkeypatch.setattr(os, "splice", fail_forward)
                task = asyncio.create_task(
                    client._connect_pipelined(
                        Target("destination.example", 443),
                        source,
                        byte_budget=4096,
                        call_budget=3,
                    )
                )
                await entered.wait()
                if failure == "cancel":
                    task.cancel()
                    error = asyncio.CancelledError
                elif failure == "splice":
                    await loop.sock_sendall(sender, b"wake splice failure")
                    error = OSError
                elif failure == "timeout":
                    error = TimeoutError
                else:
                    error = UpstreamRejected
                with pytest.raises(error):
                    await task
                assert finalized.is_set()
                assert upstream_sock is not None and upstream_sock.fileno() == -1
                assert source.fileno() >= 0, "the caller retains its source socket"
                await closed.wait()
                await asyncio.gather(*tuple(service.tasks))
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_both_pipes_are_allocated_before_connect_and_reclaimed_on_failure(monkeypatch):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        closed = asyncio.Event()
        original_pipe2 = os.pipe2
        allocations = 0

        def fail_second_pipe(flags):
            nonlocal allocations
            allocations += 1
            if allocations == 2:
                raise OSError(errno.EMFILE, "injected second staged pipe failure")
            return original_pipe2(flags)

        async def proxy(reader, writer):
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()
            assert await reader.read() == b"", "pipe failure must precede CONNECT"
            closed.set()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with local_pair() as (source, _sender):
                monkeypatch.setattr(os, "pipe2", fail_second_pipe)
                with pytest.raises(
                    OSError, match="injected second staged pipe failure"
                ):
                    await client._connect_pipelined(
                        Target("destination.example", 443),
                        source,
                        byte_budget=4096,
                        call_budget=3,
                    )
                assert allocations == 2
                assert source.fileno() >= 0
                await closed.wait()
                await asyncio.gather(*tuple(service.tasks))
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
