"""SOCKS control-plane checks over local socketpairs, without TCP networking."""

import asyncio
import errno
import functools
import os
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit import (
    BoundAddress,
    ProtocolError,
    RejectTarget,
    ServerOptions,
    Socks5Client,
    Socks5RewriteServer,
    Target,
    UpstreamRejected,
)
from socks5_kit._io import read_address, read_exact, read_request
from socks5_kit.protocol import decode_address, encode_address, encode_reply

from .local_io import install_local_io, local_pair, recv, run, sendall


@pytest.mark.parametrize(
    "address",
    [
        Target(IPv4Address("192.0.2.1"), 80),
        Target(IPv6Address("2001:db8::1"), 443),
        Target("MiXeD_service.example.", 53),
        Target("127.0.0.1", 8080),
        Target("例子.测试", 443),
        BoundAddress(IPv4Address("0.0.0.0"), 0),
        BoundAddress(IPv6Address("::"), 0),
        BoundAddress("unknown", 0),
    ],
)
def test_address_roundtrip_retains_type_and_payload_boundary(address):
    wire = encode_address(address)
    decoded, consumed = decode_address(wire + b"application payload")
    assert (decoded.kind, decoded.host, decoded.port) == (
        address.kind,
        address.host,
        address.port,
    )
    assert consumed == len(wire)


@pytest.mark.parametrize(
    "wire, reply",
    [(b"", 1), (b"\x01\x00", 1), (b"\x99", 8), (b"\x03\x00\x00\x50", 8)],
)
def test_unusable_addresses_fail_explicitly(wire, reply):
    with pytest.raises(ProtocolError) as failure:
        decode_address(wire)
    assert failure.value.reply == reply


@pytest.mark.parametrize(
    "target", [Target("destination", 80), Target(IPv6Address("::1"), 9)]
)
def test_client_handshake_leaves_coalesced_payload_in_socket(monkeypatch, target):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (connection, peer):

            async def open_socket(_client):
                return connection

            monkeypatch.setattr(Socks5Client, "_open_socket", open_socket)
            bound = BoundAddress("MiXeD_bound.example", 0)
            payload = b"\x00\xffunbuffered payload" * 4096

            async def proxy():
                assert await read_exact(peer, 3) == b"\x05\x01\x00"
                await sendall(peer, b"\x05\x00")
                command, requested = await read_request(peer)
                assert command == 1
                assert (requested.kind, requested.host, requested.port) == (
                    target.kind,
                    target.host,
                    target.port,
                )
                reply = bytearray(encode_reply(0, bound))
                reply[2] = 91
                await sendall(peer, reply + payload)
                assert await read_exact(peer, 3) == b"ack"
                peer.close()

            task = asyncio.create_task(proxy())
            async with await Socks5Client("127.0.0.1", 1081).connect(target) as tunnel:
                assert tunnel.bound_address == bound
                result = bytearray()
                while len(result) < len(payload):
                    result.extend(await tunnel.recv(1024))
                assert result == payload
                await tunnel.sendall(b"ack")
                await task
                assert await tunnel.recv() == b""
            assert connection.fileno() == -1

    run(scenario)


@pytest.mark.parametrize("reply", [2, 5, 7, 9])
def test_client_preserves_minimal_upstream_failure(monkeypatch, reply):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (connection, peer):

            async def open_socket(_client):
                return connection

            monkeypatch.setattr(Socks5Client, "_open_socket", open_socket)

            async def proxy():
                await read_exact(peer, 3)
                await sendall(peer, b"\x05\x00")
                await read_request(peer)
                await sendall(peer, bytes([5, reply, 77]))

            task = asyncio.create_task(proxy())
            with pytest.raises(UpstreamRejected) as failure:
                await Socks5Client("127.0.0.1", 1081).connect(Target("x", 80))
            assert failure.value.reply == reply
            await task
            assert connection.fileno() == -1

    run(scenario)


@pytest.mark.parametrize("failure", ["timeout", "cancel", "method", "address"])
def test_client_cleans_up_failed_handshake(monkeypatch, failure):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (connection, peer):

            async def open_socket(_client):
                return connection

            monkeypatch.setattr(Socks5Client, "_open_socket", open_socket)
            entered = asyncio.Event()

            async def proxy():
                await read_exact(peer, 3)
                entered.set()
                if failure == "method":
                    await sendall(peer, b"\x05\xff")
                elif failure == "address":
                    await sendall(peer, b"\x05\x00")
                    await read_request(peer)
                    await sendall(peer, b"\x05\x00\x00\x99")

            proxy_task = asyncio.create_task(proxy())
            client = Socks5Client("127.0.0.1", 1081, handshake_timeout=0.02)
            task = asyncio.create_task(client.connect(Target("x", 80)))
            await entered.wait()
            if failure == "cancel":
                task.cancel()
            expected = {"timeout": TimeoutError, "cancel": asyncio.CancelledError}.get(
                failure, ProtocolError
            )
            with pytest.raises(expected) as error:
                await task
            if failure in ("method", "address"):
                assert error.value.reply == 1
            await proxy_task
            assert connection.fileno() == -1

    run(scenario)


@pytest.mark.parametrize(
    "behavior, command, reply",
    [
        ("none", 1, 2),
        ("reject", 1, 2),
        ("ip", 1, 1),
        ("timeout", 1, 1),
        ("exception", 1, 1),
        ("none", 2, 7),
        ("none", 3, 7),
    ],
)
def test_server_rejection_never_opens_upstream(monkeypatch, behavior, command, reply):
    async def scenario():
        install_local_io(monkeypatch)
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (connection, peer):
            calls = []

            async def rewrite(target, context):
                calls.append((target, context))
                if behavior == "reject":
                    raise RejectTarget()
                if behavior == "ip":
                    return Target(IPv4Address("127.0.0.1"), 80)
                if behavior == "timeout":
                    await asyncio.Event().wait()
                if behavior == "exception":
                    raise ValueError("bad rule")
                return None

            async def unexpected_connect(_client, _target):
                raise AssertionError("upstream must not be opened")

            monkeypatch.setattr(Socks5Client, "connect", unexpected_connect)
            server = Socks5RewriteServer(
                rewrite,
                "127.0.0.1",
                1081,
                options=ServerOptions(callback_timeout=0.02),
            )
            server._loop = asyncio.get_running_loop()
            server._state = "running"
            task = asyncio.create_task(
                server._serve_connection(connection, ("::1", 99), 1)
            )
            server._sessions.add(task)
            task.add_done_callback(functools.partial(server._session_done, connection))
            await sendall(
                peer,
                b"\x05\x02\x80\x00"
                + bytes([5, command, 99])
                + encode_address(Target(IPv6Address("2001:db8::9"), 80)),
            )
            assert await read_exact(peer, 2) == b"\x05\x00"
            assert await read_exact(peer, 3) == bytes([5, reply, 0])
            assert await read_address(peer) == BoundAddress(IPv4Address("0.0.0.0"), 0)
            assert await recv(peer, 1) == b""
            await task
            await server.aclose()
            assert len(calls) == (1 if command == 1 else 0)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_server_maps_target_and_hands_unbuffered_payload_to_relay(monkeypatch):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (connection, peer), local_pair() as (upstream, proxy_peer):
            original = Target(IPv4Address("192.0.2.1"), 80)
            rewritten = Target("destination.example", 443)
            bound = BoundAddress(IPv6Address("2001:db8::4"), 12345)
            outgoing, incoming = b"client payload\x00\xff", b"upstream payload\x00\xff"
            calls = []
            relay_closed = []

            async def open_socket(_client):
                return upstream

            async def rewrite(target, context):
                assert target == original
                assert context.client_endpoint == ("127.0.0.1", 99)
                assert context.session_id == context.flow_id == 42
                assert context.username is context.password is None
                calls.append(target)
                return rewritten

            class Relay:
                def __init__(self, left, right, **_budgets):
                    self.left, self.right = left, right

                async def run(self):
                    assert await read_exact(self.left, len(outgoing)) == outgoing
                    assert await read_exact(self.right, len(incoming)) == incoming

                def close(self):
                    relay_closed.append(True)

            monkeypatch.setattr(Socks5Client, "_open_socket", open_socket)
            monkeypatch.setattr("socks5_kit.server.SpliceRelay", Relay)
            server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
            server._loop = asyncio.get_running_loop()
            server._state = "running"

            async def proxy():
                assert await read_exact(proxy_peer, 3) == b"\x05\x01\x00"
                await sendall(proxy_peer, b"\x05\x00")
                assert await read_exact(proxy_peer, 3) == b"\x05\x01\x00"
                assert await read_address(proxy_peer) == BoundAddress(
                    rewritten.host, rewritten.port
                )
                await sendall(proxy_peer, encode_reply(0, bound) + incoming)

            task = asyncio.create_task(
                server._serve_connection(connection, ("127.0.0.1", 99), 42)
            )
            proxy_task = asyncio.create_task(proxy())
            await sendall(
                peer, b"\x05\x01\x00\x05\x01\x7f" + encode_address(original) + outgoing
            )
            assert await read_exact(peer, 2) == b"\x05\x00"
            assert await read_exact(peer, 3) == b"\x05\x00\x00"
            assert await read_address(peer) == bound
            assert await recv(peer, 1) == b""
            await asyncio.gather(task, proxy_task)
            await server.aclose()
            assert len(calls) == len(relay_closed) == 1
            assert upstream.fileno() == connection.fileno() == -1

    run(scenario)


def test_socket_initialization_failure_closes_socket(monkeypatch):
    class FailingSocket:
        closed = False

        def setblocking(self, _value):
            pass

        def setsockopt(self, *_args):
            raise OSError(errno.EPERM, "injected socket option failure")

        def close(self):
            self.closed = True

    async def scenario():
        failed = FailingSocket()
        monkeypatch.setattr("socks5_kit.client.socket.socket", lambda *_args: failed)
        with pytest.raises(OSError, match="injected socket option failure"):
            await Socks5Client("127.0.0.1", 1081).connect(Target("x", 80))
        assert failed.closed
        monkeypatch.undo()  # Restore socket type before asyncio closes its self-pipe.

    run(scenario)


@pytest.mark.parametrize("cancel_close", [False, True])
def test_server_close_cancels_pending_callback_and_is_idempotent(
    monkeypatch, cancel_close
):
    async def scenario():
        install_local_io(monkeypatch)
        baseline = len(os.listdir("/proc/self/fd"))
        entered = asyncio.Event()

        async def rewrite(_target, _context):
            entered.set()
            await asyncio.Event().wait()

        with local_pair() as (connection, peer):
            server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
            server._loop = asyncio.get_running_loop()
            server._state = "running"
            task = asyncio.create_task(
                server._serve_connection(connection, ("127.0.0.1", 9), 1)
            )
            server._sessions.add(task)
            task.add_done_callback(functools.partial(server._session_done, connection))
            await sendall(
                peer,
                b"\x05\x01\x00\x05\x01\x00" + encode_address(Target("x", 80)),
            )
            assert await read_exact(peer, 2) == b"\x05\x00"
            await entered.wait()
            closing = asyncio.create_task(server.aclose(grace_period=0.02))
            if cancel_close:
                await asyncio.sleep(0.001)
                closing.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await closing
            else:
                await closing
            assert task.cancelled()
            assert server.active_connections == 0
            assert await recv(peer, 1) == b""
            await server.aclose()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_accepted_socket_cancelled_before_handler_entry_is_closed():
    async def scenario():
        with local_pair() as (connection, _peer):
            server = Socks5RewriteServer(lambda _t, _c: None, "127.0.0.1", 1081)
            task = asyncio.create_task(
                server._serve_connection(connection, ("127.0.0.1", 9), 1)
            )
            server._sessions.add(task)
            task.add_done_callback(functools.partial(server._session_done, connection))
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)
            assert connection.fileno() == -1
            assert server.active_connections == 0

    run(scenario)


def test_pipe_allocation_failure_sends_failure_and_reclaims_first_pipe(monkeypatch):
    async def scenario():
        install_local_io(monkeypatch)
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (connection, peer), local_pair() as (upstream, proxy_peer):

            async def open_socket(_client):
                return upstream

            monkeypatch.setattr(Socks5Client, "_open_socket", open_socket)
            original = os.pipe2
            calls = 0

            def allocate(flags):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError(errno.EMFILE, "injected pipe failure")
                return original(flags)

            monkeypatch.setattr(os, "pipe2", allocate)
            server = Socks5RewriteServer(
                lambda _t, _c: Target("destination", 80), "127.0.0.1", 1081
            )
            server._loop = asyncio.get_running_loop()
            server._state = "running"

            async def proxy():
                await read_exact(proxy_peer, 3)
                await sendall(proxy_peer, b"\x05\x00")
                await read_request(proxy_peer)
                await sendall(proxy_peer, encode_reply(0))

            task = asyncio.create_task(
                server._serve_connection(connection, ("127.0.0.1", 9), 1)
            )
            proxy_task = asyncio.create_task(proxy())
            await sendall(
                peer,
                b"\x05\x01\x00\x05\x01\x00"
                + encode_address(Target(IPv4Address("192.0.2.1"), 80)),
            )
            assert await read_exact(peer, 2) == b"\x05\x00"
            assert await read_exact(peer, 3) == b"\x05\x01\x00"
            await read_address(peer)
            assert await recv(peer, 1) == b""
            await asyncio.gather(task, proxy_task)
            await server.aclose()
            assert calls == 2
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
