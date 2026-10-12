"""An importable no-auth SOCKS5 TCP client using exclusively owned raw sockets."""

import asyncio
import ipaddress
import math
import socket
from dataclasses import dataclass
from typing import Self

from ._io import read_exact, read_reply
from .errors import ProtocolError
from .models import BoundAddress, Target
from .protocol import NO_AUTH, VERSION, encode_connect


@dataclass(slots=True)
class TcpTunnel:
    """Owns the connected socket; the caller must close it or use async with.

    Handshake bytes are consumed exactly. Any application bytes remain in the
    socket receive queue. Do not mix these helpers with another socket reader.
    """

    socket: socket.socket
    bound_address: BoundAddress
    _loop: asyncio.AbstractEventLoop

    def _check_loop(self) -> None:
        if asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("tunnel must be used on its original event loop")

    async def recv(self, size: int = 65536) -> bytes:
        self._check_loop()
        if size <= 0:
            raise ValueError("receive size must be positive")
        return await self._loop.sock_recv(self.socket, size)

    async def sendall(self, data: bytes) -> None:
        self._check_loop()
        await self._loop.sock_sendall(self.socket, data)

    def shutdown_write(self) -> None:
        self.socket.shutdown(socket.SHUT_WR)

    def close(self) -> None:
        self.socket.close()

    async def aclose(self) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_exc) -> None:
        self.close()


class Socks5Client:
    """Configuration only; connect() creates one independently owned TCP tunnel."""

    def __init__(
        self,
        ip: str,
        port: int,
        *,
        connect_timeout: float = 10.0,
        handshake_timeout: float = 10.0,
    ) -> None:
        self.ip = str(ipaddress.ip_address(ip))
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("upstream port must be in 1..65535")
        for value in (connect_timeout, handshake_timeout):
            if isinstance(value, bool) or not isinstance(value, (float, int)):
                raise TypeError("timeouts must be numbers")
            if not math.isfinite(value) or value <= 0:
                raise ValueError("timeouts must be finite and positive")
        self.port = port
        self.connect_timeout = connect_timeout
        self.handshake_timeout = handshake_timeout

    async def _open_socket(self) -> socket.socket:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in self.ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            async with asyncio.timeout(self.connect_timeout):
                await loop.sock_connect(sock, (self.ip, self.port))
            return sock
        except BaseException:
            sock.close()
            raise

    async def connect(self, target: Target, *, initial_data: bytes = b"") -> TcpTunnel:
        """Open a tunnel, optionally pipelining payload with the CONNECT frame.

        ``initial_data`` is sent before the SOCKS reply and may reach the target
        before the proxy reports success. It is not replayed or acknowledged by
        this client. The returned socket retains all bytes after the reply.
        """
        if not isinstance(target, Target):
            raise TypeError("target must be a Target")
        if not isinstance(initial_data, bytes):
            raise TypeError("initial_data must be bytes")
        loop = asyncio.get_running_loop()
        sock = await self._open_socket()
        try:
            async with asyncio.timeout(self.handshake_timeout):
                await loop.sock_sendall(sock, bytes([VERSION, 1, NO_AUTH]))
                version, method = await read_exact(sock, 2)
                if version != VERSION or method != NO_AUTH:
                    raise ProtocolError("upstream does not accept SOCKS5 no-auth")
                await loop.sock_sendall(sock, encode_connect(target) + initial_data)
                bound = await read_reply(sock)
            return TcpTunnel(sock, bound, loop)
        except ProtocolError as exc:
            sock.close()
            raise ProtocolError(f"invalid upstream handshake: {exc}") from exc
        except BaseException:
            sock.close()
            raise
