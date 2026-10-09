"""Credentials stay with their downstream session across the real TCP relay."""

import asyncio
import hashlib

import pytest

from socks5_kit import (
    BoundAddress,
    RejectTarget,
    ServerOptions,
    Socks5Client,
    Socks5RewriteServer,
    Target,
)
from socks5_kit.protocol import encode_address, encode_reply
from tests.test_tcp import (
    Service,
    downstream_reply,
    eventually_closed,
    idle,
    run,
    upstream_request,
)

pytestmark = pytest.mark.tcp_loopback


def auth_frame(username, password):
    return (
        b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    )


def connect_frame(target):
    return b"\x05\x01\x00" + encode_address(target)


def test_auth_is_preferred_and_pipelined_payload_survives_half_close():
    async def scenario():
        calls = []
        received_targets = []
        username, password = b"\xff\x00sample-user", b"sample-\xfe\xff\x00"
        original = Target("original.example", 443)
        rewritten = Target("rewritten.example", 9443)
        payload = bytes(range(256)) * 8192
        prefix = b"immediate upstream bytes\x00\xff"
        digest = hashlib.sha256(payload).digest()

        async def upstream(reader, writer):
            # The internal SOCKS client still negotiates no authentication.
            received_targets.append(await upstream_request(reader, writer))
            writer.write(encode_reply(0) + prefix)
            await writer.drain()
            received = await reader.read()
            assert received == payload
            writer.write(hashlib.sha256(received).digest())
            await writer.drain()

        async with Service(upstream) as proxy:

            async def rewrite(target, context):
                calls.append((target, context.username, context.password))
                await asyncio.sleep(0)
                return rewritten

            server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
            async with server:
                await server.start(port=0)
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    # 00 appears before 02: selection must be by preference.
                    writer.write(
                        b"\x05\x03\x00\x80\x02"
                        + auth_frame(username, password)
                        + connect_frame(original)
                        + payload
                    )
                    await writer.drain()
                    assert await reader.readexactly(2) == b"\x05\x02"
                    assert await reader.readexactly(2) == b"\x01\x00"
                    reply, _bound = await downstream_reply(reader)
                    assert reply == 0
                    assert await reader.readexactly(len(prefix)) == prefix
                    writer.write_eof()
                    assert await reader.read() == digest
                finally:
                    writer.close()
                    await writer.wait_closed()
                await eventually_closed(server)
                assert calls == [(original, username, password)]
                assert received_targets == [
                    BoundAddress(rewritten.host, rewritten.port)
                ]

    run(scenario)


def test_no_authentication_passes_none_credentials():
    async def scenario():
        calls = []

        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(0) + b"response")
            await writer.drain()

        async with Service(upstream) as proxy:

            def rewrite(target, context):
                calls.append((target, context.username, context.password))
                return target

            server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
            async with server:
                await server.start(port=0)
                target = Target("destination.example", 80)
                client = Socks5Client(*server.address)
                async with await client.connect(target) as tunnel:
                    received = bytearray()
                    while data := await tunnel.recv():
                        received.extend(data)
                    assert received == b"response"
                await eventually_closed(server)
                assert calls == [(target, None, None)]

    run(scenario)


@pytest.mark.parametrize("refusal", ["none", "exception"])
def test_credential_policy_rejects_connect_before_opening_upstream(refusal):
    async def scenario():
        calls = []
        username, password = b"denied-user", b"denied-value"

        async with Service(idle) as proxy:

            def rewrite(target, context):
                calls.append((target, context.username, context.password))
                if refusal == "exception":
                    raise RejectTarget("credential policy refusal")
                return None

            server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
            async with server:
                await server.start(port=0)
                target = Target("destination.example", 443)
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(
                        b"\x05\x01\x02"
                        + auth_frame(username, password)
                        + connect_frame(target)
                    )
                    assert await reader.readexactly(4) == b"\x05\x02\x01\x00"
                    reply, _bound = await downstream_reply(reader)
                    assert reply == 2
                    assert await reader.read() == b""
                finally:
                    writer.close()
                    await writer.wait_closed()
                await eventually_closed(server)
                assert calls == [(target, username, password)]
                assert proxy.connections == 0

    run(scenario)


@pytest.mark.parametrize("credentials", [(b"", b""), (b"", b"p"), (b"u", b"")])
def test_empty_credentials_are_distinct_from_no_authentication(credentials):
    async def scenario():
        calls = []

        def rewrite(_target, context):
            calls.append((context.username, context.password))
            return None

        server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
        async with server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(
                    b"\x05\x01\x02"
                    + auth_frame(*credentials)
                    + connect_frame(Target("destination.example", 80))
                )
                assert await reader.readexactly(4) == b"\x05\x02\x01\x00"
                reply, _bound = await downstream_reply(reader)
                assert reply == 2
                assert await reader.read() == b""
            finally:
                writer.close()
                await writer.wait_closed()
            await eventually_closed(server)
            assert calls == [credentials]

    run(scenario)


def test_concurrent_authentication_keeps_credentials_and_payloads_separate():
    async def scenario():
        calls = []
        both_callbacks = asyncio.Event()

        async def upstream(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(0))
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(upstream) as proxy:

            async def rewrite(target, context):
                calls.append((target, context))
                if len(calls) == 2:
                    both_callbacks.set()
                await both_callbacks.wait()
                return Target("rewritten.example", target.port)

            server = Socks5RewriteServer(rewrite, "127.0.0.1", proxy.port)
            async with server:
                await server.start(port=0)

                async def flow(index):
                    username = bytes([index, 0xFF, 0])
                    password = bytes([0xFE, index])
                    payload = bytes([index]) * (128 * 1024)
                    target = Target(f"flow-{index}.example", 9000 + index)
                    reader, writer = await asyncio.open_connection(*server.address)
                    try:
                        writer.write(b"\x05\x01\x02")
                        assert await reader.readexactly(2) == b"\x05\x02"
                        # Deliver credentials in fragments, then pipeline CONNECT/data.
                        for value in auth_frame(username, password):
                            writer.write(bytes([value]))
                            await writer.drain()
                            await asyncio.sleep(0)
                        assert await reader.readexactly(2) == b"\x01\x00"
                        writer.write(connect_frame(target) + payload)
                        await writer.drain()
                        reply, _bound = await downstream_reply(reader)
                        assert reply == 0
                        assert await reader.readexactly(len(payload)) == payload
                        writer.write_eof()
                        assert await reader.read() == b""
                    finally:
                        writer.close()
                        await writer.wait_closed()
                    return target, username, password

                expected = await asyncio.gather(flow(1), flow(2))
                await eventually_closed(server)
                assert sorted(
                    (target.host, context.username, context.password)
                    for target, context in calls
                ) == sorted(
                    (target.host, username, password)
                    for target, username, password in expected
                )
                assert len({context.session_id for _target, context in calls}) == 2
                assert proxy.connections == 2

    run(scenario)


@pytest.mark.parametrize("failure", ["version", "eof", "timeout", "shutdown"])
def test_incomplete_or_invalid_authentication_never_runs_callback(failure):
    async def scenario():
        calls = []

        async with Service(idle) as proxy:

            def rewrite(_target, _context):
                calls.append(True)
                return Target("destination.example", 80)

            options = ServerOptions(handshake_timeout=0.1)
            server = Socks5RewriteServer(
                rewrite, "127.0.0.1", proxy.port, options=options
            )
            async with server:
                await server.start(port=0)
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(b"\x05\x01\x02")
                    assert await reader.readexactly(2) == b"\x05\x02"
                    if failure == "version":
                        writer.write(b"\x02")
                        assert await reader.readexactly(2) == b"\x01\x01"
                    else:
                        writer.write(b"\x01\x04ab")
                        await writer.drain()
                        if failure == "eof":
                            writer.write_eof()
                        elif failure == "shutdown":
                            await asyncio.sleep(0)
                            await server.aclose()
                    assert await reader.read() == b""
                finally:
                    writer.close()
                    await writer.wait_closed()
                await eventually_closed(server)
                assert calls == []
                assert proxy.connections == 0

    run(scenario)


def test_no_acceptable_method_rejects_without_callback():
    async def scenario():
        calls = []

        def rewrite(_target, _context):
            calls.append(True)
            return None

        server = Socks5RewriteServer(rewrite, "127.0.0.1", 1081)
        async with server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(b"\x05\x02\x01\x80")
                assert await reader.readexactly(2) == b"\x05\xff"
                assert await reader.read() == b""
            finally:
                writer.close()
                await writer.wait_closed()
            await eventually_closed(server)
            assert calls == []

    run(scenario)
