"""An importable SOCKS5 TCP client using exclusively owned raw sockets."""

import asyncio
import ipaddress
import itertools
import logging
import math
import socket
import time
from dataclasses import dataclass
from typing import Self

from ._credentials import validate_credentials
from ._io import read_exact, read_reply
from ._linux.splice import SpliceRelay
from ._logging import failure_level
from .errors import ProtocolError
from .models import BoundAddress, Target
from .protocol import NO_AUTH, USERNAME_PASSWORD, VERSION, encode_connect

logger = logging.getLogger(__name__)
_client_ids = itertools.count(1)


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
        self._client_id = next(_client_ids)
        self._sequence = itertools.count(1)

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

    async def connect(
        self,
        target: Target,
        *,
        initial_data: bytes = b"",
        credentials: tuple[str, str] | None = None,
    ) -> TcpTunnel:
        """Open a tunnel, optionally pipelining payload with the CONNECT frame.

        ``initial_data`` is sent before the SOCKS reply and may reach the target
        before the proxy reports success. It is not replayed or acknowledged by
        this client. The returned socket retains all bytes after the reply.

        ``credentials`` uses UTF-8 username/password authentication for this
        connection only. Configured credentials never fall back to no-auth.
        """
        tunnel, _relay = await self._connect(
            target, initial_data=initial_data, credentials=credentials
        )
        return tunnel

    async def _connect_pipelined(
        self,
        target: Target,
        source: socket.socket,
        *,
        credentials: tuple[str, str] | None = None,
        byte_budget: int = 256 * 1024,
        call_budget: int = 8,
    ) -> tuple[TcpTunnel, SpliceRelay]:
        """Reverse addon: stream payload before REP, leaving reverse splice paused."""
        tunnel, relay = await self._connect(
            target,
            source=source,
            credentials=credentials,
            byte_budget=byte_budget,
            call_budget=call_budget,
        )
        assert relay is not None
        return tunnel, relay

    async def _connect(
        self,
        target: Target,
        *,
        initial_data: bytes = b"",
        source: socket.socket | None = None,
        credentials: tuple[str, str] | None = None,
        byte_budget: int = 256 * 1024,
        call_budget: int = 8,
    ) -> tuple[TcpTunnel, SpliceRelay | None]:
        if not isinstance(target, Target):
            raise TypeError("target must be a Target")
        if not isinstance(initial_data, bytes):
            raise TypeError("initial_data must be bytes")
        credentials = validate_credentials(credentials)
        if credentials is None:
            method = NO_AUTH
            auth_frame = None
        else:
            method = USERNAME_PASSWORD
            username, password = (value.encode("utf-8") for value in credentials)
            auth_frame = (
                bytes([1, len(username)]) + username + bytes([len(password)]) + password
            )
        loop = asyncio.get_running_loop()
        session_id = next(self._sequence)
        started = time.monotonic()
        stage = "proxy_connect"
        sock: socket.socket | None = None
        relay: SpliceRelay | None = None
        try:
            logger.debug(
                "SOCKS client connecting client_id=%s session_id=%s proxy=%r "
                "target=%r pipelined=%s",
                self._client_id,
                session_id,
                (self.ip, self.port),
                target,
                source is not None,
            )
            sock = await self._open_socket()
            async with asyncio.timeout(self.handshake_timeout):
                stage = "method_negotiation"
                await loop.sock_sendall(sock, bytes([VERSION, 1, method]))
                version, selected_method = await read_exact(sock, 2)
                if version != VERSION or selected_method != method:
                    description = (
                        "no-auth" if method == NO_AUTH else "username/password"
                    )
                    raise ProtocolError(
                        f"upstream does not accept SOCKS5 {description}"
                    )
                if auth_frame is not None:
                    stage = "authentication"
                    await loop.sock_sendall(sock, auth_frame)
                    auth_version, auth_status = await read_exact(sock, 2)
                    if auth_version != 1 or auth_status != 0:
                        raise ProtocolError(
                            "upstream username/password authentication failed"
                        )
                if source is not None:
                    relay = SpliceRelay(
                        source, sock, byte_budget=byte_budget, call_budget=call_budget
                    )
                stage = "connect_reply"
                await loop.sock_sendall(sock, encode_connect(target) + initial_data)
                if relay is None:
                    bound = await read_reply(sock)
                else:
                    relay.start(forward_only=True)
                    bound = await relay.read_handshake(read_reply(sock))
            logger.info(
                "SOCKS client established client_id=%s session_id=%s proxy=%r "
                "target=%r bound=%r elapsed_ms=%.3f",
                self._client_id,
                session_id,
                (self.ip, self.port),
                target,
                bound,
                (time.monotonic() - started) * 1000,
            )
            return TcpTunnel(sock, bound, loop), relay
        except ProtocolError as exc:
            self._log_failure(session_id, target, stage, started, exc)
            if relay is not None:
                relay.close()
            if sock is not None:
                sock.close()
            raise ProtocolError(f"invalid upstream handshake: {exc}") from exc
        except BaseException as exc:
            if isinstance(exc, Exception):
                self._log_failure(session_id, target, stage, started, exc)
            else:
                logger.debug(
                    "SOCKS client cancelled client_id=%s session_id=%s proxy=%r "
                    "target=%r stage=%s",
                    self._client_id,
                    session_id,
                    (self.ip, self.port),
                    target,
                    stage,
                )
            if relay is not None:
                relay.close()
            if sock is not None:
                sock.close()
            raise

    def _log_failure(
        self,
        session_id: int,
        target: Target,
        stage: str,
        started: float,
        error: Exception,
    ) -> None:
        logger.log(
            failure_level(error),
            "SOCKS client failed client_id=%s session_id=%s proxy=%r target=%r "
            "stage=%s error_type=%s elapsed_ms=%.3f",
            self._client_id,
            session_id,
            (self.ip, self.port),
            target,
            stage,
            type(error).__name__,
            (time.monotonic() - started) * 1000,
        )
