"""Per-connection credentials preserve handshake and streaming byte boundaries."""

import asyncio
import logging
import socket
from ipaddress import IPv4Address

import pytest

from socks5_kit import BoundAddress, ProtocolError, Socks5Client, Target
from socks5_kit._io import read_exact
from socks5_kit.protocol import encode_reply

from .local_io import local_pair
from .test_tcp import Service, run, stream_address

pytestmark = pytest.mark.tcp_loopback


async def credentials_from_wire(reader, writer, *, fragmented=False):
    assert await reader.readexactly(3) == b"\x05\x01\x02"
    if fragmented:
        writer.write(b"\x05")
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(b"\x02")
    else:
        writer.write(b"\x05\x02")
    await writer.drain()
    version, username_length = await reader.readexactly(2)
    assert version == 1
    username = await reader.readexactly(username_length)
    password_length = (await reader.readexactly(1))[0]
    password = await reader.readexactly(password_length)
    return username, password


@pytest.mark.parametrize(
    "credentials",
    [("", ""), ("alice", "secret"), ("用户", "päss"), ("x" * 255, "y" * 255)],
)
def test_credentials_are_per_call_utf8_and_connect_payload_waits_for_auth(credentials):
    async def scenario():
        bound = BoundAddress(IPv4Address("127.0.0.1"), 4000)
        target = Target("destination.example", 443)
        payload = b"pipelined registration HELLO"
        banner = b"coalesced business banner\x00\xff"

        async def proxy(reader, writer):
            assert await credentials_from_wire(reader, writer, fragmented=True) == (
                tuple(value.encode("utf-8") for value in credentials)
            )
            writer.write(b"\x01")
            await writer.drain()
            await asyncio.sleep(0)
            writer.write(b"\x00")
            await writer.drain()
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            assert await stream_address(reader) == BoundAddress(
                target.host, target.port
            )
            assert await reader.readexactly(len(payload)) == payload
            writer.write(encode_reply(0, bound) + banner)
            await writer.drain()
            assert await reader.read() == b""

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            async with await client.connect(
                target, credentials=credentials, initial_data=payload
            ) as tunnel:
                assert tunnel.bound_address == bound
                assert await read_exact(tunnel.socket, len(banner)) == banner
            await asyncio.gather(*tuple(service.tasks))

    run(scenario)


def test_coalesced_auth_reply_connect_reply_and_data_are_consumed_exactly():
    async def scenario():
        banner = b"unsolicited target greeting"

        async def proxy(reader, writer):
            assert await credentials_from_wire(reader, writer) == (b"u", b"p")
            # A permissive peer can coalesce all responses before reading CONNECT.
            writer.write(b"\x01\x00" + encode_reply(0) + banner)
            await writer.drain()
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            assert await stream_address(reader) == BoundAddress("target.example", 80)
            assert await reader.read() == b""

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            async with await client.connect(
                Target("target.example", 80), credentials=("u", "p")
            ) as tunnel:
                assert await read_exact(tunnel.socket, len(banner)) == banner
            await asyncio.gather(*tuple(service.tasks))

    run(scenario)


@pytest.mark.parametrize(
    ("credentials", "selection"),
    [
        (("user", "password"), b"\x05\x00"),
        (("u", "p"), b"\x05\xff"),
        (("u", "p"), b"\x04\x02"),
        (None, b"\x05\x02"),
    ],
)
def test_unoffered_auth_method_or_wrong_version_closes_without_connect(
    credentials, selection
):
    async def scenario():
        closed = asyncio.Event()

        async def proxy(reader, writer):
            expected = b"\x05\x01\x00" if credentials is None else b"\x05\x01\x02"
            assert await reader.readexactly(3) == expected
            writer.write(selection)
            await writer.drain()
            assert await reader.read() == b""
            closed.set()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with pytest.raises(ProtocolError, match="invalid upstream handshake"):
                await client.connect(
                    Target("target.example", 80),
                    credentials=credentials,
                    initial_data=b"must not leak before authentication",
                )
            await closed.wait()
            await asyncio.gather(*tuple(service.tasks))

    run(scenario)


@pytest.mark.parametrize("reply", [b"\x01\x01", b"\x00\x00", b"\x01", b""])
def test_auth_failure_sends_no_connect_or_initial_data_and_logs_no_password(
    reply, caplog
):
    async def scenario():
        closed = asyncio.Event()
        secret = "private-password-never-log-this"

        async def proxy(reader, writer):
            assert await credentials_from_wire(reader, writer) == (
                b"user",
                secret.encode(),
            )
            writer.write(reply)
            await writer.drain()
            if len(reply) < 2:
                writer.write_eof()
                await writer.drain()
            assert await reader.read() == b""
            closed.set()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with caplog.at_level(logging.DEBUG):
                with pytest.raises(ProtocolError) as exc:
                    await client.connect(
                        Target("target.example", 80),
                        credentials=("user", secret),
                        initial_data=b"must not reach unauthenticated peer",
                    )
                assert secret not in str(exc.value)
                assert secret not in caplog.text
            await closed.wait()
            await asyncio.gather(*tuple(service.tasks))

    run(scenario)


@pytest.mark.parametrize("failure", ["timeout", "cancel"])
def test_partial_auth_reply_timeout_or_cancel_closes_owned_socket(failure, monkeypatch):
    async def scenario():
        entered = asyncio.Event()
        closed = asyncio.Event()
        owned_socket = None

        async def proxy(reader, writer):
            assert await credentials_from_wire(reader, writer) == (b"user", b"password")
            writer.write(b"\x01")
            await writer.drain()
            entered.set()
            try:
                assert await reader.read() == b""
            except ConnectionResetError:
                # Cancel can close before consuming the first response byte.
                pass
            closed.set()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port, handshake_timeout=0.2)
            original_open = client._open_socket

            async def tracked_open():
                nonlocal owned_socket
                owned_socket = await original_open()
                return owned_socket

            monkeypatch.setattr(client, "_open_socket", tracked_open)
            task = asyncio.create_task(
                client.connect(
                    Target("target.example", 80),
                    credentials=("user", "password"),
                    initial_data=b"never sent before successful authentication",
                )
            )
            await entered.wait()
            if failure == "cancel":
                task.cancel()
                expected = asyncio.CancelledError
            else:
                expected = TimeoutError
            with pytest.raises(expected):
                await task
            assert owned_socket is not None and owned_socket.fileno() == -1
            await closed.wait()
            await asyncio.gather(*tuple(service.tasks))

    run(scenario)


@pytest.mark.parametrize(
    ("credentials", "error"),
    [
        ([], TypeError),
        (["user", "password"], TypeError),
        (("user",), TypeError),
        (("u", "p", "extra"), TypeError),
        ((b"user", "p"), TypeError),
        (("u", None), TypeError),
        (("x" * 256, "p"), ValueError),
        (("u", "é" * 128), ValueError),
        (("u", "private-password\ud800"), ValueError),
    ],
)
def test_invalid_credentials_fail_before_socket_io(credentials, error, monkeypatch):
    async def scenario():
        client = Socks5Client("127.0.0.1", 1)

        async def forbidden_open():
            pytest.fail("invalid credentials must be rejected before opening a socket")

        monkeypatch.setattr(client, "_open_socket", forbidden_open)
        with pytest.raises(error) as exc:
            await client.connect(Target("target.example", 80), credentials=credentials)
        assert "private-password" not in str(exc.value)

    run(scenario)


def test_same_client_uses_noauth_or_empty_username_independently():
    async def scenario():
        methods = []

        async def proxy(reader, writer):
            version, count, method = await reader.readexactly(3)
            assert (version, count) == (5, 1)
            methods.append(method)
            writer.write(bytes([5, method]))
            await writer.drain()
            if method == 2:
                assert await reader.readexactly(3) == b"\x01\x00\x00"
                writer.write(b"\x01\x00")
                await writer.drain()
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            await stream_address(reader)
            writer.write(encode_reply(0))
            await writer.drain()
            await reader.read()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            for credentials in (None, ("", ""), None):
                async with await client.connect(
                    Target("target.example", 80), credentials=credentials
                ):
                    pass
                await asyncio.gather(*tuple(service.tasks))
            assert methods == [0, 2, 0]

    run(scenario)


def test_authenticated_pipelined_payload_and_eof_precede_connect_reply():
    async def scenario():
        loop = asyncio.get_running_loop()
        payload = bytes(range(256)) * 8192
        response = b"target response after REP"
        received = asyncio.Event()
        reply_allowed = asyncio.Event()

        async def proxy(reader, writer):
            assert await credentials_from_wire(reader, writer) == (b"user", b"password")
            writer.write(b"\x01\x00")
            await writer.drain()
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            assert await stream_address(reader) == BoundAddress("target.example", 80)
            assert await reader.readexactly(len(payload)) == payload
            assert await reader.read() == b""
            received.set()
            await reply_allowed.wait()
            writer.write(encode_reply(0) + response)
            await writer.drain()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with local_pair() as (source, sender):

                async def send():
                    await loop.sock_sendall(sender, payload)
                    sender.shutdown(socket.SHUT_WR)

                send_task = asyncio.create_task(send())
                connect_task = asyncio.create_task(
                    client._connect_pipelined(
                        Target("target.example", 80),
                        source,
                        credentials=("user", "password"),
                        byte_budget=4096,
                        call_budget=3,
                    )
                )
                await received.wait()
                assert not connect_task.done()
                await send_task
                reply_allowed.set()
                tunnel, relay = await connect_task
                try:
                    relay.start_reverse()
                    assert await read_exact(sender, len(response)) == response
                    assert await loop.sock_recv(sender, 1) == b""
                    await relay.wait()
                finally:
                    relay.close()
                    tunnel.close()

    run(scenario)
