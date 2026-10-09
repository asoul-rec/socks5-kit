"""Inbound authentication framing over local socketpairs."""

import asyncio

import pytest

from socks5_kit import ProtocolError, Target
from socks5_kit._io import negotiate_server, read_exact, read_request
from socks5_kit.protocol import USERNAME_PASSWORD, encode_connect

from .local_io import install_local_io, local_pair, run, sendall


def auth_frame(username, password):
    return bytes([1, len(username)]) + username + bytes([len(password)]) + password


@pytest.mark.parametrize(
    "methods",
    [b"\x02", b"\x00\x02", b"\x02\x00", b"\x80\xff\x00\x02\x02"],
)
def test_username_password_has_priority_regardless_of_method_order(
    monkeypatch, methods
):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            await sendall(client, bytes([5, len(methods)]) + methods)
            assert await read_exact(client, 2) == bytes([5, USERNAME_PASSWORD])
            await sendall(client, auth_frame(b"user", b"password"))
            assert await read_exact(client, 2) == b"\x01\x00"
            assert await task == (b"user", b"password")

    run(scenario)


@pytest.mark.parametrize("methods", [b"\x00", b"\x80\x00", b"\x00\xff\x00"])
def test_no_auth_fallback_preserves_connect_bytes(monkeypatch, methods):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            target = Target("destination.example", 443)
            task = asyncio.create_task(negotiate_server(server))
            await sendall(
                client, bytes([5, len(methods)]) + methods + encode_connect(target)
            )
            assert await read_exact(client, 2) == b"\x05\x00"
            assert await task == (None, None)
            command, address = await read_request(server)
            assert command == 1
            assert (address.host, address.port) == (target.host, target.port)

    run(scenario)


@pytest.mark.parametrize("methods", [b"", b"\x01", b"\x80\xff", b"\xff" * 255])
def test_no_acceptable_method_returns_refusal(monkeypatch, methods):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            await sendall(client, bytes([5, len(methods)]) + methods)
            assert await read_exact(client, 2) == b"\x05\xff"
            assert await task is None

    run(scenario)


@pytest.mark.parametrize(
    "username,password",
    [
        (b"", b""),
        (b"", b"secret"),
        (b"name", b""),
        (b"\x00\xff\xc0\x80", b"\xff\x00\xfe"),
        (bytes(range(255)), bytes(range(255, 0, -1))),
    ],
)
def test_credentials_are_raw_bytes_and_coalesced_payload_is_not_consumed(
    monkeypatch, username, password
):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            target = Target("destination.example", 443)
            payload = b"\x00\xffapplication data" * 1024
            task = asyncio.create_task(negotiate_server(server))
            await sendall(
                client,
                b"\x05\x02\x00\x02"
                + auth_frame(username, password)
                + encode_connect(target)
                + payload,
            )
            assert await read_exact(client, 4) == b"\x05\x02\x01\x00"
            assert await task == (username, password)
            command, address = await read_request(server)
            assert command == 1
            assert (address.host, address.port) == (target.host, target.port)
            assert await read_exact(server, len(payload)) == payload

    run(scenario)


def test_greeting_and_authentication_can_arrive_one_byte_at_a_time(monkeypatch):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            for byte in b"\x05\x02\x00\x02":
                await sendall(client, bytes([byte]))
                await asyncio.sleep(0)
            assert await read_exact(client, 2) == b"\x05\x02"
            for byte in auth_frame(b"username", b"password"):
                await sendall(client, bytes([byte]))
                await asyncio.sleep(0)
            assert await read_exact(client, 2) == b"\x01\x00"
            assert await task == (b"username", b"password")

    run(scenario)


@pytest.mark.parametrize("version", [0, 2, 5, 255])
def test_wrong_auth_version_fails_without_waiting_for_remaining_frame(
    monkeypatch, version
):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            await sendall(client, b"\x05\x01\x02")
            assert await read_exact(client, 2) == b"\x05\x02"
            await sendall(client, bytes([version]))
            assert await read_exact(client, 2) == b"\x01\x01"
            assert await task is None

    run(scenario)


@pytest.mark.parametrize(
    "partial_auth",
    [b"", b"\x01", b"\x01\x03", b"\x01\x03ab", b"\x01\x01x", b"\x01\x00\x02p"],
)
def test_truncated_authentication_raises_protocol_error(monkeypatch, partial_auth):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            await sendall(client, b"\x05\x01\x02")
            assert await read_exact(client, 2) == b"\x05\x02"
            await sendall(client, partial_auth)
            client.close()
            with pytest.raises(ProtocolError, match="EOF inside handshake"):
                await task

    run(scenario)


@pytest.mark.parametrize("partial_greeting", [b"", b"\x05", b"\x05\x02\x00"])
def test_truncated_greeting_raises_protocol_error(monkeypatch, partial_greeting):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            task = asyncio.create_task(negotiate_server(server))
            await sendall(client, partial_greeting)
            client.close()
            with pytest.raises(ProtocolError, match="EOF inside handshake"):
                await task

    run(scenario)


def test_wrong_socks_version_raises_protocol_error(monkeypatch):
    async def scenario():
        install_local_io(monkeypatch)
        with local_pair() as (server, client):
            await sendall(client, b"\x04\x00")
            with pytest.raises(ProtocolError, match="only SOCKS5 is supported"):
                await negotiate_server(server)

    run(scenario)
