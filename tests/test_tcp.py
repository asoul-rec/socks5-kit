"""Loopback integration checks for wire compatibility and the real splice path."""

import asyncio
import errno
import hashlib
import os
import socket
import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit import (
    AddressType,
    BoundAddress,
    RejectTarget,
    ServerOptions,
    Socks5Client,
    Socks5RewriteServer,
    Target,
    UpstreamRejected,
)
from socks5_kit.protocol import Command, decode_address, encode_address, encode_reply

pytestmark = pytest.mark.tcp_loopback


class Service:
    """Track accepted transports immediately, including tasks cancelled before entry."""

    def __init__(self, handler, *, host="127.0.0.1"):
        self.handler = handler
        self.host = host
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.connections = 0

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.accept, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    def accept(self, reader, writer):
        self.connections += 1
        self.writers.add(writer)
        task = asyncio.create_task(self.run(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def run(self, reader, writer):
        try:
            await self.handler(reader, writer)
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        except Exception as exc:
            self.errors.append(exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.writers.discard(writer)

    async def __aexit__(self, exc_type, _exc, _tb):
        self.server.close()
        await self.server.wait_closed()
        for writer in self.writers:
            writer.close()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for writer in list(self.writers):
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
        if exc_type is None:
            assert not self.errors, self.errors


async def stream_address(reader):
    atyp = await reader.readexactly(1)
    if atyp[0] == AddressType.DOMAIN:
        size = await reader.readexactly(1)
        data = atyp + size + await reader.readexactly(size[0] + 2)
    else:
        size = 4 if atyp[0] == AddressType.IPV4 else 16
        data = atyp + await reader.readexactly(size + 2)
    address, _ = decode_address(data)
    return address


async def upstream_request(reader, writer):
    assert await reader.readexactly(3) == b"\x05\x01\x00"
    writer.write(b"\x05\x00")
    await writer.drain()
    assert await reader.readexactly(3) == b"\x05\x01\x00"
    return await stream_address(reader)


async def downstream_reply(reader):
    version, reply, reserved = await reader.readexactly(3)
    assert version == 5 and reserved == 0
    return reply, await stream_address(reader)


async def request(server, target, *, payload=b"", command=Command.CONNECT):
    reader, writer = await asyncio.open_connection(*server.address)
    # Method negotiation, request and application payload intentionally coalesced.
    writer.write(
        b"\x05\x02\x80\x00"
        + bytes([5, command, 0x7F])
        + encode_address(target)
        + payload
    )
    assert await reader.readexactly(2) == b"\x05\x00"
    reply, bound = await downstream_reply(reader)
    return reader, writer, reply, bound


async def bridge(left_reader, left_writer, right_reader, right_writer):
    async def copy(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.write_eof()
        await writer.drain()

    async with asyncio.TaskGroup() as group:
        group.create_task(copy(left_reader, right_writer))
        group.create_task(copy(right_reader, left_writer))


async def idle(reader, _writer):
    await reader.read()


async def eventually_closed(server):
    async with asyncio.timeout(2):
        await asyncio.gather(*tuple(server._sessions), return_exceptions=True)
        await asyncio.sleep(0)
    assert server.active_connections == 0


def run(scenario):
    async def bounded():
        async with asyncio.timeout(15):
            await scenario()

    asyncio.run(bounded())


@pytest.mark.parametrize(
    "original",
    [
        Target(IPv4Address("192.0.2.10"), 9000),
        Target(IPv6Address("2001:db8::10"), 9000),
        Target("MiXeD_service.example.", 9000),
    ],
)
def test_rewrite_real_target_and_pipelined_payload(original):
    async def scenario():
        calls = []
        received_targets = []
        payload = bytes(range(256)) * 8192
        prefix = b"immediate upstream payload\x00\xff"
        bound = BoundAddress(IPv6Address("2001:db8::9"), 2345)

        async def echo(reader, writer):
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(echo) as destination:

            async def upstream(reader, writer):
                target = await upstream_request(reader, writer)
                received_targets.append(target)
                assert target.kind == AddressType.DOMAIN
                target_reader, target_writer = await asyncio.open_connection(
                    target.host, target.port
                )
                try:
                    # Nonzero inbound RSV is tolerated; forwarded reply is canonical.
                    reply = bytearray(encode_reply(0, bound))
                    reply[2] = 0x7F
                    writer.write(reply + prefix)
                    await writer.drain()
                    await bridge(reader, writer, target_reader, target_writer)
                finally:
                    target_writer.close()
                    await target_writer.wait_closed()

            async with Service(upstream) as proxy:

                async def rewrite(target, context):
                    calls.append((target, context))
                    await asyncio.sleep(0)
                    return Target("localhost", destination.port)

                server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
                async with server:
                    await server.start(port=0)
                    reader, writer, reply, received_bound = await request(
                        server, original, payload=payload
                    )
                    assert reply == 0 and received_bound == bound
                    assert await reader.readexactly(len(prefix) + len(payload)) == (
                        prefix + payload
                    )
                    writer.write_eof()
                    assert await reader.read() == b""
                    writer.close()
                    await writer.wait_closed()
                    await eventually_closed(server)
                    assert len(calls) == 1 and calls[0][0] == original
                    context = calls[0][1]
                    assert (
                        context.transport == "tcp" and context.direction == "outbound"
                    )
                    assert context.client_endpoint[0] == "127.0.0.1"
                    assert context.session_id == context.flow_id
                    assert received_targets == [
                        BoundAddress("localhost", destination.port)
                    ]

    run(scenario)


def test_half_close_drains_every_byte_before_delayed_response():
    async def scenario():
        payload = bytes(range(256)) * 16384
        digest = hashlib.sha256(payload).digest()

        async def destination_handler(reader, writer):
            received = await reader.read()
            assert received == payload
            # Reply only after receiving EOF; the opposite relay direction must survive.
            writer.write(hashlib.sha256(received).digest())
            await writer.drain()

        async with Service(destination_handler) as destination:

            async def upstream(reader, writer):
                await upstream_request(reader, writer)
                target_reader, target_writer = await asyncio.open_connection(
                    "127.0.0.1", destination.port
                )
                try:
                    writer.write(encode_reply(0))
                    await writer.drain()
                    await bridge(reader, writer, target_reader, target_writer)
                finally:
                    target_writer.close()
                    await target_writer.wait_closed()

            async with Service(upstream) as proxy:
                server = Socks5RewriteServer(
                    lambda _t, _c: Target("localhost", destination.port),
                    "127.0.0.1",
                    proxy.port,
                )
                async with server:
                    await server.start(port=0)
                    reader, writer, reply, _bound = await request(
                        server, Target("original.example", 9000)
                    )
                    assert reply == 0
                    writer.write(payload)
                    await writer.drain()
                    writer.write_eof()
                    assert await reader.read() == digest
                    writer.close()
                    await writer.wait_closed()
                    await eventually_closed(server)

    run(scenario)


@pytest.mark.parametrize("behavior", ["none", "exception", "ip", "timeout"])
def test_callback_refusal_and_failure_do_not_connect_upstream(behavior):
    async def scenario():
        async with Service(idle) as proxy:

            async def rewrite(_target, _context):
                if behavior == "exception":
                    raise RejectTarget("policy refusal")
                if behavior == "ip":
                    return Target(IPv4Address("127.0.0.1"), 80)
                if behavior == "timeout":
                    await asyncio.Event().wait()
                return None

            server = Socks5RewriteServer(
                rewrite,
                "127.0.0.1",
                proxy.port,
                options=ServerOptions(callback_timeout=0.02),
            )
            async with server:
                await server.start(port=0)
                reader, writer, reply, _bound = await request(
                    server, Target("original.example", 80)
                )
                assert reply == (2 if behavior in ("none", "exception") else 1)
                assert await reader.read() == b""
                writer.close()
                await writer.wait_closed()
                await eventually_closed(server)
                assert proxy.connections == 0

    run(scenario)


@pytest.mark.parametrize("reply", [2, 5, 7, 9])
def test_upstream_failure_rep_is_preserved_even_without_bnd_fields(reply):
    async def scenario():
        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(bytes([5, reply, 0]))
            await writer.drain()

        async with Service(upstream) as proxy:
            server = Socks5RewriteServer(
                lambda _t, _c: Target("rewritten.example", 80),
                "127.0.0.1",
                proxy.port,
            )
            async with server:
                await server.start(port=0)
                reader, writer, received, _bound = await request(
                    server, Target(IPv4Address("192.0.2.1"), 80)
                )
                assert received == reply
                assert await reader.read() == b""
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.parametrize("command", [Command.BIND, Command.UDP_ASSOCIATE, 99])
def test_unimplemented_commands_are_explicitly_rejected(command):
    async def scenario():
        def rewrite(_t, _c):
            pytest.fail("unsupported commands must not run callback")

        server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
        async with server:
            await server.start(port=0)
            reader, writer, reply, _bound = await request(
                server, BoundAddress(IPv4Address("0.0.0.0"), 0), command=command
            )
            assert reply == 7
            assert await reader.read() == b""
            writer.close()
            await writer.wait_closed()

    run(scenario)


def test_public_client_preserves_immediate_payload_and_bound_address():
    async def scenario():
        payload = b"payload sent with SOCKS reply\x00\xff"
        bound = BoundAddress("Unusual_bound.example", 0)

        async def upstream(reader, writer):
            target = await upstream_request(reader, writer)
            assert target == BoundAddress("destination.example", 443)
            writer.write(encode_reply(0, bound) + payload)
            await writer.drain()

        async with Service(upstream) as proxy:
            client = Socks5Client("127.0.0.1", proxy.port)
            async with await client.connect(
                Target("destination.example", 443)
            ) as tunnel:
                assert tunnel.bound_address == bound
                received = bytearray()
                while data := await tunnel.recv(7):
                    received.extend(data)
                assert received == payload

    run(scenario)


def test_shutdown_cancels_callback_and_reclaims_all_session_fds():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        callback_entered = asyncio.Event()

        async def rewrite(_t, _c):
            callback_entered.set()
            await asyncio.Event().wait()

        server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
        await server.start(port=0)
        reader, writer = await asyncio.open_connection(*server.address)
        writer.write(b"\x05\x01\x00\x05\x01\x00" + encode_address(Target("x", 80)))
        assert await reader.readexactly(2) == b"\x05\x00"
        await callback_entered.wait()
        await server.aclose()
        await server.aclose()
        assert server.active_connections == 0
        assert await reader.read() == b""
        writer.close()
        await writer.wait_closed()
        assert len(os.listdir("/proc/self/fd")) == baseline
        with pytest.raises(RuntimeError):
            await server.start(port=0)

    run(scenario)


def test_pipe_allocation_failure_before_success_reply_has_no_fd_leak(monkeypatch):
    async def scenario():
        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(0))
            await writer.drain()
            await reader.read()

        async with Service(upstream) as proxy:
            server = Socks5RewriteServer(
                lambda _t, _c: Target("rewritten.example", 80),
                "127.0.0.1",
                proxy.port,
            )
            async with server:
                await server.start(port=0)
                baseline = len(os.listdir("/proc/self/fd"))
                original_pipe2 = os.pipe2
                calls = 0

                def fail_second_pipe(flags):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise OSError(errno.EMFILE, "injected FD exhaustion")
                    return original_pipe2(flags)

                monkeypatch.setattr(os, "pipe2", fail_second_pipe)
                reader, writer, reply, _bound = await request(
                    server, Target("original.example", 80)
                )
                assert reply == 1  # Must not have sent success before pipe allocation.
                assert await reader.read() == b""
                writer.close()
                await writer.wait_closed()
                await eventually_closed(server)
                await asyncio.gather(*tuple(proxy.tasks))
                await asyncio.sleep(0)
                assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_cancelled_close_still_finishes_cleanup():
    async def scenario():
        server = Socks5RewriteServer(lambda _t, _c: None, "127.0.0.1", 1081)
        await server.start(port=0)
        reader, writer = await asyncio.open_connection(*server.address)
        writer.write(b"\x05\x01\x00")  # Stall before the CONNECT request.
        assert await reader.readexactly(2) == b"\x05\x00"
        closing = asyncio.create_task(server.aclose(grace_period=0.03))
        await asyncio.sleep(0.005)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert server.active_connections == 0
        assert await reader.read() == b""
        writer.close()
        await writer.wait_closed()

    run(scenario)


def test_client_exposes_upstream_rejection():
    async def scenario():
        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(b"\x05\x02\x00")
            await writer.drain()

        async with Service(upstream) as proxy:
            with pytest.raises(UpstreamRejected) as failure:
                await Socks5Client("127.0.0.1", proxy.port).connect(Target("x", 80))
            assert failure.value.reply == 2

    run(scenario)


@pytest.mark.parametrize(
    "client_host, ipv6_only", [("::1", True), ("127.0.0.1", False)]
)
def test_ipv6_upstream_and_ipv6_or_dual_stack_listener(client_host, ipv6_only):
    async def scenario():
        contexts = []
        payload = b"IPv6 and dual stack\x00\xff" * 8192

        async def upstream(reader, writer):
            assert await upstream_request(reader, writer) == BoundAddress(
                "destination.example", 443
            )
            writer.write(encode_reply(0, BoundAddress(IPv6Address("::1"), 0)))
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(upstream, host="::1") as proxy:

            def rewrite(_target, context):
                contexts.append(context)
                return Target("destination.example", 443)

            server = Socks5RewriteServer(
                rewrite,
                "::1",
                proxy.port,
                options=ServerOptions(ipv6_only=ipv6_only),
            )
            async with server:
                await server.start(host="::" if not ipv6_only else "::1", port=0)
                async with await Socks5Client(client_host, server.address[1]).connect(
                    Target(IPv6Address("2001:db8::10"), 443)
                ) as tunnel:
                    assert tunnel.bound_address == BoundAddress(IPv6Address("::1"), 0)
                    await tunnel.sendall(payload)
                    remaining = bytearray()
                    while len(remaining) < len(payload):
                        chunk = await tunnel.recv(len(payload) - len(remaining))
                        assert chunk
                        remaining.extend(chunk)
                    assert remaining == payload
                    tunnel.shutdown_write()
                    assert await tunnel.recv() == b""
                await eventually_closed(server)
                assert len(contexts) == 1
                assert contexts[0].client_endpoint[0] == client_host

    run(scenario)


def test_connection_limit_closes_excess_connection_without_callback():
    async def scenario():
        def rewrite(_target, _context):
            pytest.fail("no CONNECT request was sent")

        server = Socks5RewriteServer(
            rewrite, "127.0.0.1", 1081, options=ServerOptions(max_connections=1)
        )
        async with server:
            await server.start(port=0)
            first_reader, first_writer = await asyncio.open_connection(*server.address)
            first_writer.write(b"\x05\x01\x00")
            assert await first_reader.readexactly(2) == b"\x05\x00"
            second_reader, second_writer = await asyncio.open_connection(
                *server.address
            )
            try:
                assert await second_reader.read() == b""
                assert server.active_connections == 1
            finally:
                second_writer.close()
                first_writer.close()
                await asyncio.gather(
                    second_writer.wait_closed(), first_writer.wait_closed()
                )
            await eventually_closed(server)

    run(scenario)


def test_concurrent_bidirectional_tunnels_keep_payload_and_callbacks_separate():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        callbacks = []
        upstream_targets = []

        async def upstream(reader, writer):
            target = await upstream_request(reader, writer)
            upstream_targets.append(target)
            writer.write(encode_reply(0))
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(upstream) as proxy:

            def rewrite(target, context):
                callbacks.append((target, context))
                return Target(f"flow-{target.port}.example", target.port)

            server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
            async with server:
                await server.start(port=0)

                async def flow(index):
                    payload = bytes([index]) * (256 * 1024) + index.to_bytes(2)
                    reader, writer, reply, _bound = await request(
                        server, Target(IPv4Address("192.0.2.1"), 10000 + index)
                    )
                    assert reply == 0

                    async def sending():
                        try:
                            for offset in range(0, len(payload), 16384):
                                writer.write(payload[offset : offset + 16384])
                                await writer.drain()
                            writer.write_eof()
                            await writer.drain()
                        except BaseException:
                            writer.close()
                            raise

                    sender = asyncio.create_task(sending())
                    try:
                        assert await reader.read() == payload
                        await sender
                    finally:
                        sender.cancel()
                        await asyncio.gather(sender, return_exceptions=True)
                        writer.close()
                        await writer.wait_closed()

                async with asyncio.TaskGroup() as group:
                    for index in range(32):
                        group.create_task(flow(index))
                await eventually_closed(server)
                assert len(callbacks) == len(upstream_targets) == 32
                assert len({context.session_id for _target, context in callbacks}) == 32
                assert {target.host for target in upstream_targets} == {
                    f"flow-{10000 + index}.example" for index in range(32)
                }
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_upstream_reset_after_success_closes_tunnel_and_reclaims_fds():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        reset_now = asyncio.Event()
        upstream_finished = asyncio.Event()

        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(0))
            await writer.drain()
            await reset_now.wait()
            writer.get_extra_info("socket").setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            writer.transport.abort()
            upstream_finished.set()

        async with Service(upstream) as proxy:
            server = Socks5RewriteServer(
                lambda _t, _c: Target("destination.example", 80),
                "127.0.0.1",
                proxy.port,
            )
            async with server:
                await server.start(port=0)
                reader, writer, reply, _bound = await request(
                    server, Target("original.example", 80)
                )
                assert reply == 0
                reset_now.set()
                await upstream_finished.wait()
                try:
                    assert await reader.read() == b""
                except ConnectionResetError:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionResetError:
                        pass
                await eventually_closed(server)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
