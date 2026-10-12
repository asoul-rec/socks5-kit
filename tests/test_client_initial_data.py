"""CONNECT payload is sent before the proxy reply, without consuming later data."""

import asyncio
import os
from ipaddress import IPv6Address

import pytest

from socks5_kit import BoundAddress, Socks5Client, Target, UpstreamRejected
from socks5_kit.protocol import encode_reply
from tests.test_tcp import Service, run, upstream_request

pytestmark = pytest.mark.tcp_loopback


def test_initial_payload_precedes_reply_and_coalesced_response_remains_in_tunnel():
    async def scenario():
        initial = b"registration hello\x00\xff"
        response = b"registration ACK followed by another frame"
        bound = BoundAddress(IPv6Address("::1"), 4321)

        async def proxy(reader, writer):
            requested = await upstream_request(reader, writer)
            assert requested == BoundAddress("reverse.example", 443)
            # Withholding REP until payload arrives proves the client does not
            # wait for REP before providing the carrier's first application bytes.
            assert await reader.readexactly(len(initial)) == initial
            writer.write(encode_reply(0, bound) + response)
            await writer.drain()
            assert await reader.read() == b""

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            async with await client.connect(
                Target("reverse.example", 443), initial_data=initial
            ) as tunnel:
                assert tunnel.bound_address == bound
                received = b""
                while len(received) < len(response):
                    chunk = await tunnel.recv(len(response) - len(received))
                    assert chunk
                    received += chunk
                assert received == response

    run(scenario)


def test_initial_payload_then_socks_rejection_closes_client_socket():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        rejected = asyncio.Event()

        async def proxy(reader, writer):
            await upstream_request(reader, writer)
            assert await reader.readexactly(6) == b"hello!"
            writer.write(encode_reply(5))
            await writer.drain()
            try:
                assert await reader.read() == b""
            except ConnectionResetError:
                # The client may leave failure BND bytes unread before closing.
                pass
            rejected.set()

        async with Service(proxy) as service:
            client = Socks5Client("127.0.0.1", service.port)
            with pytest.raises(UpstreamRejected) as raised:
                await client.connect(
                    Target("reverse.example", 443), initial_data=b"hello!"
                )
            assert raised.value.reply == 5
            await rejected.wait()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize("invalid", [None, "hello", bytearray(b"hello"), 1])
def test_invalid_initial_payload_is_rejected_before_opening_socket(
    invalid, monkeypatch
):
    async def scenario():
        client = Socks5Client("127.0.0.1", 1080)

        async def unexpected_socket():
            pytest.fail("invalid initial_data must not open a socket")

        monkeypatch.setattr(client, "_open_socket", unexpected_socket)
        with pytest.raises(TypeError, match="initial_data must be bytes"):
            await client.connect(Target("reverse.example", 443), initial_data=invalid)

    run(scenario)
