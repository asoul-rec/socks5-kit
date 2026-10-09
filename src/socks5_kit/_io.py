"""Exact socket reads for handshake ownership without payload prefetch."""

import asyncio
import socket

from .errors import ProtocolError, UpstreamRejected
from .models import AddressType, BoundAddress
from .protocol import (
    NO_ACCEPTABLE_METHOD,
    NO_AUTH,
    USERNAME_PASSWORD,
    VERSION,
    ReplyCode,
    decode_address,
)

_AUTH_VERSION = 1


async def read_exact(sock: socket.socket, size: int) -> bytes:
    loop = asyncio.get_running_loop()
    result = bytearray()
    while len(result) < size:
        chunk = await loop.sock_recv(sock, size - len(result))
        if not chunk:
            raise ProtocolError("EOF inside handshake")
        result.extend(chunk)
    return bytes(result)


async def read_address(sock: socket.socket) -> BoundAddress:
    atyp = await read_exact(sock, 1)
    if atyp[0] == AddressType.DOMAIN:
        length = await read_exact(sock, 1)
        data = atyp + length + await read_exact(sock, length[0] + 2)
    elif atyp[0] in (AddressType.IPV4, AddressType.IPV6):
        size = 4 if atyp[0] == AddressType.IPV4 else 16
        data = atyp + await read_exact(sock, size + 2)
    else:
        raise ProtocolError("unsupported address type", ReplyCode.ADDRESS_NOT_SUPPORTED)
    address, _ = decode_address(data)
    return address


async def negotiate_server(
    sock: socket.socket,
) -> tuple[bytes | None, bytes | None] | None:
    """Collect credentials for rewrite policy, without validating their contents.

    No-auth returns ``(None, None)``; failed negotiation returns ``None``.
    Username/password values remain bytes, including empty values from peers.
    """
    version, count = await read_exact(sock, 2)
    if version != VERSION:
        raise ProtocolError("only SOCKS5 is supported")
    methods = await read_exact(sock, count)
    if USERNAME_PASSWORD in methods:
        method = USERNAME_PASSWORD
    elif NO_AUTH in methods:
        method = NO_AUTH
    else:
        method = NO_ACCEPTABLE_METHOD
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, bytes([VERSION, method]))
    if method == NO_ACCEPTABLE_METHOD:
        return None
    if method == NO_AUTH:
        return None, None

    auth_version = (await read_exact(sock, 1))[0]
    if auth_version != _AUTH_VERSION:
        await loop.sock_sendall(sock, bytes([_AUTH_VERSION, 1]))
        return None
    username_length = (await read_exact(sock, 1))[0]
    username = await read_exact(sock, username_length)
    password_length = (await read_exact(sock, 1))[0]
    password = await read_exact(sock, password_length)
    # CONNECT carries the target needed by rewrite, which applies the policy.
    await loop.sock_sendall(sock, bytes([_AUTH_VERSION, 0]))
    return username, password


async def read_request(sock: socket.socket) -> tuple[int, BoundAddress]:
    version, command, _reserved = await read_exact(sock, 3)
    if version != VERSION:
        raise ProtocolError("invalid SOCKS request version")
    # Reserved bytes do not affect parsing. Outgoing messages always use zero.
    return command, await read_address(sock)


async def read_reply(sock: socket.socket) -> BoundAddress:
    version, reply, _reserved = await read_exact(sock, 3)
    if version != VERSION:
        raise ProtocolError("invalid upstream reply version")
    if reply:
        # A refusal needs no usable BND endpoint; tolerate absent/odd trailing fields.
        raise UpstreamRejected(reply)
    return await read_address(sock)
