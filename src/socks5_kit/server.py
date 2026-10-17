"""Embeddable SOCKS5 TCP target rewriting and Linux splice relay."""

import asyncio
import errno
import functools
import inspect
import ipaddress
import itertools
import logging
import math
import socket
import time
from typing import Self

from ._io import negotiate_server, read_request
from ._linux.splice import SpliceRelay, ensure_supported
from ._logging import failure_level, log_event
from .client import Socks5Client, TcpTunnel
from .errors import ProtocolError, RejectTarget, UpstreamRejected
from .models import AddressType, RewriteCallback, RewriteContext, ServerOptions, Target
from .protocol import Command, ReplyCode, encode_reply

logger = logging.getLogger(__name__)
_server_ids = itertools.count(1)


def _peer_endpoint(peer: tuple) -> tuple[str, int]:
    address = ipaddress.ip_address(peer[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address), peer[1]


class Socks5RewriteServer:
    """One upstream tunnel per CONNECT, with credentials passed to rewrite policy.

    Construction performs no I/O. Start and all lifecycle calls must use the
    same asyncio loop. A server cannot be restarted after closing.
    """

    def __init__(
        self,
        rewrite: RewriteCallback,
        upstream_ip: str,
        upstream_port: int,
        *,
        options: ServerOptions | None = None,
    ) -> None:
        if not callable(rewrite):
            raise TypeError("rewrite must be callable")
        if options is not None and not isinstance(options, ServerOptions):
            raise TypeError("options must be ServerOptions")
        self._rewrite = rewrite
        self._options = options or ServerOptions()
        self._client = Socks5Client(
            upstream_ip,
            upstream_port,
            connect_timeout=self._options.upstream_connect_timeout,
            handshake_timeout=self._options.upstream_handshake_timeout,
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task | None = None
        self._sessions: set[asyncio.Task] = set()
        self._sequence = itertools.count(1)
        self._lock = asyncio.Lock()
        self._stopped = asyncio.Event()
        self._state = "new"
        self._accept_error: BaseException | None = None
        self._close_task: asyncio.Task | None = None
        self._server_id = next(_server_ids)

    @property
    def upstream_ip(self) -> str:
        return self._client.ip

    @property
    def upstream_port(self) -> int:
        return self._client.port

    @property
    def address(self) -> tuple[str, int]:
        """Actual listener endpoint, useful when start(port=0) selects a port."""
        if self._listener is None:
            raise RuntimeError("server is not listening")
        address = self._listener.getsockname()
        return address[0], address[1]

    @property
    def active_connections(self) -> int:
        return len(self._sessions)

    def _check_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("server must be used on its original event loop")
        return loop

    async def start(self, host: str = "127.0.0.1", port: int = 1080) -> None:
        loop = self._check_loop()
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            raise ValueError("listen port must be in 0..65535")
        async with self._lock:
            if self._state != "new":
                raise RuntimeError("server can only be started once")
            ensure_supported(loop)
            self._loop = loop
            addresses = await loop.getaddrinfo(
                host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
            )
            last_error: OSError | None = None
            for family, kind, proto, _name, endpoint in addresses:
                listener = None
                try:
                    listener = socket.socket(family, kind, proto)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == socket.AF_INET6:
                        listener.setsockopt(
                            socket.IPPROTO_IPV6,
                            socket.IPV6_V6ONLY,
                            int(self._options.ipv6_only),
                        )
                    listener.setblocking(False)
                    listener.bind(endpoint)
                    listener.listen(self._options.backlog)
                except OSError as exc:
                    last_error = exc
                    if listener is not None:
                        listener.close()
                    continue
                self._listener = listener
                break
            if self._listener is None:
                raise last_error or OSError("no usable listener address")
            self._state = "running"
            self._accept_task = loop.create_task(self._accept_loop())
            self._accept_task.add_done_callback(self._accept_done)
            logger.info(
                "SOCKS rewrite server started server_id=%s listener=%r proxy=%r "
                "max_connections=%s",
                self._server_id,
                self.address,
                (self.upstream_ip, self.upstream_port),
                self._options.max_connections,
            )

    def _accept_done(self, task: asyncio.Task) -> None:
        if not task.cancelled():
            self._accept_error = task.exception()
        self._stopped.set()
        if self._accept_error is not None and self._state == "running":
            self._state = "closing"
            self._close_task = self._check_loop().create_task(self._close(0.0, None))

    async def _accept_loop(self) -> None:
        assert self._loop is not None and self._listener is not None
        while True:
            connection, peer = await self._loop.sock_accept(self._listener)
            if len(self._sessions) >= self._options.max_connections:
                logger.warning(
                    "SOCKS rewrite rejected server_id=%s listener=%r peer=%r "
                    "reason=max_connections active=%s",
                    self._server_id,
                    self.address,
                    peer,
                    len(self._sessions),
                )
                connection.close()
                continue
            try:
                connection.setblocking(False)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                task = self._loop.create_task(
                    self._serve_connection(connection, peer, next(self._sequence))
                )
            except BaseException:
                connection.close()
                raise
            self._sessions.add(task)
            task.add_done_callback(functools.partial(self._session_done, connection))

    def _session_done(self, connection: socket.socket, task: asyncio.Task) -> None:
        # A task cancelled before its first step never enters the handler's finally.
        connection.close()
        self._sessions.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled SOCKS session error", exc_info=error)

    async def _serve_connection(
        self, connection: socket.socket, peer: tuple, session_id: int
    ) -> None:
        negotiated = reply_started = False
        tunnel: TcpTunnel | None = None
        relay: SpliceRelay | None = None
        started = time.monotonic()
        stage = "handshake"
        target = rewritten = None
        logger.debug(
            "SOCKS rewrite accepted server_id=%s session_id=%s listener=%r peer=%r "
            "active=%s",
            self._server_id,
            session_id,
            connection.getsockname(),
            peer,
            self.active_connections,
        )
        try:
            async with asyncio.timeout(self._options.handshake_timeout):
                credentials = await negotiate_server(connection)
                if credentials is None:
                    logger.info(
                        "SOCKS rewrite rejected server_id=%s session_id=%s peer=%r "
                        "stage=method_negotiation reason=no_acceptable_method",
                        self._server_id,
                        session_id,
                        peer,
                    )
                    return
                negotiated = True
                command, address = await read_request(connection)
                if command != Command.CONNECT:
                    raise ProtocolError(
                        "only TCP CONNECT is implemented",
                        ReplyCode.COMMAND_NOT_SUPPORTED,
                    )
                target = Target(address.host, address.port)
            context = RewriteContext(
                "tcp",
                "outbound",
                _peer_endpoint(peer),
                session_id,
                session_id,
                username=credentials[0],
                password=credentials[1],
            )
            stage = "rewrite"
            async with asyncio.timeout(self._options.callback_timeout):
                candidate = self._rewrite(target, context)
                if inspect.isawaitable(candidate):
                    candidate = await candidate
            if candidate is None:
                raise RejectTarget("target rejected by callback")
            if (
                not isinstance(candidate, Target)
                or candidate.kind != AddressType.DOMAIN
            ):
                raise TypeError("rewrite must return a DOMAIN Target or None")
            rewritten = candidate
            if self._state != "running":
                return
            logger.info(
                "SOCKS rewrite allowed server_id=%s session_id=%s peer=%r target=%r "
                "rewritten=%r proxy=%r elapsed_ms=%.3f",
                self._server_id,
                session_id,
                peer,
                target,
                rewritten,
                (self.upstream_ip, self.upstream_port),
                (time.monotonic() - started) * 1000,
            )
            stage = "upstream_connect"
            tunnel = await self._client.connect(rewritten)
            stage = "relay_setup"
            relay = SpliceRelay(
                connection,
                tunnel.socket,
                byte_budget=self._options.splice_byte_budget,
                call_budget=self._options.splice_call_budget,
            )
            reply_started = True
            stage = "success_reply"
            async with asyncio.timeout(self._options.reply_timeout):
                await self._check_loop().sock_sendall(
                    connection, encode_reply(ReplyCode.SUCCESS, tunnel.bound_address)
                )
            stage = "relay"
            logger.info(
                "SOCKS rewrite established server_id=%s session_id=%s peer=%r "
                "target=%r rewritten=%r proxy=%r bound=%r elapsed_ms=%.3f",
                self._server_id,
                session_id,
                peer,
                target,
                rewritten,
                (self.upstream_ip, self.upstream_port),
                tunnel.bound_address,
                (time.monotonic() - started) * 1000,
            )
            await relay.run()
        except asyncio.CancelledError:
            logger.debug(
                "SOCKS rewrite cancelled server_id=%s session_id=%s peer=%r stage=%s",
                self._server_id,
                session_id,
                peer,
                stage,
            )
            raise
        except Exception as exc:
            log_event(
                logger,
                (
                    logging.DEBUG
                    if stage == "relay" and isinstance(exc, OSError)
                    else failure_level(exc)
                ),
                "socks_rewrite_failed",
                server_id=self._server_id,
                session_id=session_id,
                peer=peer,
                target=target,
                rewritten=rewritten,
                stage=stage,
                error_type=type(exc).__name__,
                elapsed_ms=round((time.monotonic() - started) * 1000, 3),
            )
            if negotiated and not reply_started:
                await self._send_failure(connection, self._failure_reply(exc))
        finally:
            if relay is not None:
                relay.close()
            if tunnel is not None:
                tunnel.close()
            connection.close()
            logger.debug(
                "SOCKS rewrite closed server_id=%s session_id=%s peer=%r stage=%s "
                "duration_ms=%.3f",
                self._server_id,
                session_id,
                peer,
                stage,
                (time.monotonic() - started) * 1000,
            )

    @staticmethod
    def _failure_reply(error: Exception) -> int:
        if isinstance(error, RejectTarget):
            return ReplyCode.NOT_ALLOWED
        if isinstance(error, (ProtocolError, UpstreamRejected)):
            return error.reply
        if isinstance(error, OSError):
            return {
                errno.ECONNREFUSED: ReplyCode.CONNECTION_REFUSED,
                errno.ENETUNREACH: ReplyCode.NETWORK_UNREACHABLE,
                errno.EHOSTUNREACH: ReplyCode.HOST_UNREACHABLE,
            }.get(error.errno, ReplyCode.GENERAL_FAILURE)
        return ReplyCode.GENERAL_FAILURE

    async def _send_failure(self, connection: socket.socket, reply: int) -> None:
        try:
            async with asyncio.timeout(self._options.reply_timeout):
                await self._check_loop().sock_sendall(connection, encode_reply(reply))
        except OSError, TimeoutError:
            pass

    async def serve_forever(self) -> None:
        self._check_loop()
        if self._state != "running":
            raise RuntimeError("start the server before serve_forever")
        try:
            await self._stopped.wait()
            if self._accept_error is not None:
                raise self._accept_error
        finally:
            await self.aclose()

    async def aclose(self, grace_period: float = 0.0) -> None:
        self._check_loop()
        if not isinstance(grace_period, (int, float)) or isinstance(grace_period, bool):
            raise TypeError("grace_period must be a number")
        if not math.isfinite(grace_period) or grace_period < 0:
            raise ValueError("grace_period must be finite and nonnegative")
        async with self._lock:
            if self._state == "closed":
                return
            if self._close_task is None:
                self._state = "closing"
                self._close_task = self._check_loop().create_task(
                    self._close(grace_period, asyncio.current_task())
                )
            closing = self._close_task
        try:
            await asyncio.shield(closing)
        except asyncio.CancelledError:
            # Finish FD cleanup even when the caller is cancelled during shutdown.
            await asyncio.shield(closing)
            raise

    async def _close(self, grace_period: float, initiator: asyncio.Task | None) -> None:
        listener = self.address if self._listener is not None else None
        try:
            if self._accept_task is not None:
                self._accept_task.cancel()
                await asyncio.gather(self._accept_task, return_exceptions=True)
            if self._listener is not None:
                self._listener.close()
                self._listener = None
            pending = set(self._sessions) - {initiator}
            if grace_period and pending:
                await asyncio.wait(pending, timeout=grace_period)
        finally:
            if self._listener is not None:
                self._listener.close()
                self._listener = None
            pending = set(self._sessions) - {initiator}
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            self._sessions.difference_update(pending)
            self._state = "closed"
            self._stopped.set()
            logger.info(
                "SOCKS rewrite server stopped server_id=%s listener=%r active=%s",
                self._server_id,
                listener,
                self.active_connections,
            )

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
