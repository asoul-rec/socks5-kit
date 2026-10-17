"""Callback DNS server with optional upstream lookup of A/AAAA alias targets."""

import asyncio
import inspect
import ipaddress
import itertools
import logging
import math
import secrets
import socket
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from ._dns_protocol import (
    DnsFormatError,
    Rcode,
    decode_upstream_address,
    encode_error,
    encode_response,
    encode_upstream_query,
    parse_query,
)
from ._logging import failure_level, log_event

__all__ = ["DnsOptions", "DnsRecordType", "DnsResolver", "DnsServer"]

logger = logging.getLogger(__name__)
_server_ids = itertools.count(1)


class DnsRecordType(IntEnum):
    A = 1
    CNAME = 5
    AAAA = 28


type DnsResult = ipaddress.IPv4Address | ipaddress.IPv6Address | str | None
type DnsResolver = Callable[[str, DnsRecordType], DnsResult | Awaitable[DnsResult]]


def _cname_labels(target: str) -> tuple[bytes, ...]:
    """Validate a DNS alias and encode its complete name without compression."""
    if target == ".":
        return ()
    target = target.encode("idna").decode("ascii").lower()
    if target.endswith("."):
        target = target[:-1]
    labels = target.split(".")
    if (
        any(not label or len(label) > 63 for label in labels)
        or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in target)
        or 1 + sum(len(label) + 1 for label in labels) > 255
    ):
        raise ValueError("CNAME target must be a valid domain of up to 255 octets")
    return tuple(label.encode("ascii") for label in labels)


@dataclass(frozen=True, slots=True)
class DnsOptions:
    ttl: int = 0
    callback_timeout: float = 10.0
    upstream_timeout: float = 2.0
    tcp_idle_timeout: float = 10.0
    max_pending_queries: int = 256
    max_tcp_connections: int = 128
    backlog: int = 128
    ipv6_only: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.ttl, bool) or not isinstance(self.ttl, int):
            raise TypeError("ttl must be an integer")
        if not 0 <= self.ttl <= 2**31 - 1:
            raise ValueError("ttl must be in 0..2147483647")
        for name in ("callback_timeout", "upstream_timeout", "tcp_idle_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name in ("max_pending_queries", "max_tcp_connections", "backlog"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if not isinstance(self.ipv6_only, bool):
            raise TypeError("ipv6_only must be a bool")


class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, owner: DnsServer, closed: asyncio.Future) -> None:
        self.owner = owner
        self.closed = closed

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.owner._datagram_received(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("DNS datagram error error_type=%s", type(exc).__name__)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.closed.done():
            self.closed.set_result(None)
        if self.owner._state == "running" and self.owner._udp_closed is self.closed:
            self.owner._check_loop().create_task(self.owner.aclose())


class DnsServer:
    """Serve A, AAAA and CNAME over UDP/TCP on the caller's asyncio loop.

    Supported IN queries call resolve(domain, qtype).
    None means NXDOMAIN; mismatched IP families yield an empty answer. A/AAAA
    aliases may be resolved with one query to upstream_dns; failure preserves
    the alias. Other types get empty answers without
    calling resolve. Construction performs no I/O. Closing is final.
    """

    def __init__(
        self,
        resolve: DnsResolver,
        *,
        upstream_dns: tuple[str, int] | None = None,
        options: DnsOptions | None = None,
    ) -> None:
        if not callable(resolve):
            raise TypeError("resolve must be callable")
        if options is not None and not isinstance(options, DnsOptions):
            raise TypeError("options must be DnsOptions")
        if upstream_dns is not None:
            if not isinstance(upstream_dns, tuple) or len(upstream_dns) != 2:
                raise TypeError("upstream_dns must be an (IP string, port) tuple")
            host, port = upstream_dns
            if not isinstance(host, str):
                raise TypeError("upstream DNS IP must be a string")
            address = ipaddress.ip_address(host)
            if (
                isinstance(address, ipaddress.IPv6Address)
                and address.scope_id is not None
            ):
                raise ValueError("upstream DNS IP cannot contain an IPv6 scope ID")
            if isinstance(port, bool) or not isinstance(port, int):
                raise TypeError("upstream DNS port must be an integer")
            if not 1 <= port <= 65535:
                raise ValueError("upstream DNS port must be in 1..65535")
            upstream_dns = str(address), port
        self._resolve = resolve
        self._upstream_dns = upstream_dns
        self._options = options or DnsOptions()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tcp_server: asyncio.Server | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._udp_closed: asyncio.Future | None = None
        self._udp_tasks: set[asyncio.Task] = set()
        self._connections: dict[asyncio.Task, asyncio.StreamWriter] = {}
        self._pending_queries = 0
        self._address: tuple[str, int] | None = None
        self._state = "new"
        self._lock = asyncio.Lock()
        self._stopped = asyncio.Event()
        self._close_task: asyncio.Task | None = None
        self._server_id = next(_server_ids)
        self._query_sequence = itertools.count(1)

    @property
    def upstream_dns(self) -> tuple[str, int] | None:
        return self._upstream_dns

    @property
    def address(self) -> tuple[str, int] | None:
        """UDP and TCP listener endpoint, or None while not listening."""
        return self._address

    @property
    def active_queries(self) -> int:
        return self._pending_queries

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    def _check_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("server must be used on its original event loop")
        return loop

    async def start(self, host: str = "127.0.0.1", port: int = 53) -> None:
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
            self._loop = loop
            addresses = await loop.getaddrinfo(
                host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
            )
            last_error: OSError | None = None
            for family, kind, proto, _name, endpoint in addresses:
                tcp = udp = None
                try:
                    tcp = socket.socket(family, kind, proto)
                    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    udp = socket.socket(family, socket.SOCK_DGRAM)
                    if family == socket.AF_INET6:
                        for sock in (tcp, udp):
                            sock.setsockopt(
                                socket.IPPROTO_IPV6,
                                socket.IPV6_V6ONLY,
                                int(self._options.ipv6_only),
                            )
                    tcp.setblocking(False)
                    udp.setblocking(False)
                    tcp.bind(endpoint)
                    endpoint = tcp.getsockname()
                    udp.bind(endpoint)
                    tcp.listen(self._options.backlog)
                except OSError as exc:
                    last_error = exc
                    if tcp is not None:
                        tcp.close()
                    if udp is not None:
                        udp.close()
                    continue
                break
            else:
                raise last_error or OSError("no usable listener address")

            server = transport = None
            udp_closed = self._udp_closed = loop.create_future()
            try:
                server = await asyncio.start_server(
                    self._accept_connection, sock=tcp, start_serving=False
                )
                transport, _protocol = await loop.create_datagram_endpoint(
                    lambda: _Datagrams(self, udp_closed), sock=udp
                )
                self._tcp_server = server
                self._udp_transport = transport
                await server.start_serving()
                self._address = endpoint[0], endpoint[1]
                self._state = "running"
                log_event(
                    logger,
                    logging.INFO,
                    "dns_server_started",
                    server_id=self._server_id,
                    listener=self._address,
                    transports="udp,tcp",
                    upstream=self._upstream_dns,
                    max_pending_queries=self._options.max_pending_queries,
                    max_tcp_connections=self._options.max_tcp_connections,
                )
            except BaseException:
                self._state = "new"
                self._address = None
                self._tcp_server = self._udp_transport = None
                if server is not None:
                    server.close()
                    await server.wait_closed()
                if transport is not None:
                    transport.close()
                    await udp_closed
                tcp.close()
                udp.close()
                raise

    async def _answer(
        self,
        packet: bytes,
        *,
        _reserved: bool = False,
        _udp: bool = False,
        _transport: str = "internal",
        _peer: tuple | None = None,
    ) -> bytes | None:
        query_id = next(self._query_sequence)
        started = time.monotonic()
        reply = await self._answer_packet(packet, _reserved=_reserved, _udp=_udp)
        if reply is not None:
            rcode = reply[3] & 0xF
            level = (
                logging.WARNING
                if rcode in (Rcode.FORMERR, Rcode.SERVFAIL)
                else logging.INFO
            )
            # Parse extra access metadata only if this response will be logged.
            if logger.isEnabledFor(level):
                try:
                    query = parse_query(packet)
                except DnsFormatError:
                    query = None
                if query is not None and query.edns_version != 0:
                    rcode = Rcode.BADVERS
                log_event(
                    logger,
                    level,
                    "dns_response",
                    server_id=self._server_id,
                    query_id=query_id,
                    listener=self._address,
                    transport=_transport,
                    peer=_peer,
                    domain=query.domain if query is not None else None,
                    qtype=query.qtype if query is not None else None,
                    rcode=int(rcode),
                    answer_count=int.from_bytes(reply[6:8]),
                    elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                )
        elif reply is None:
            logger.debug(
                "DNS packet ignored server_id=%s query_id=%s transport=%s peer=%r",
                self._server_id,
                query_id,
                _transport,
                _peer,
            )
        return reply

    async def _answer_packet(
        self, packet: bytes, *, _reserved: bool = False, _udp: bool = False
    ) -> bytes | None:
        try:
            query = parse_query(packet)
        except DnsFormatError:
            return encode_error(packet, Rcode.FORMERR)
        if query is None:
            return None
        if query.opcode != 0:
            return encode_response(query, rcode=Rcode.NOTIMP)
        if query.edns_version != 0:
            return encode_response(query, rcode=Rcode.BADVERS)
        if query.qclass != 1:
            return encode_response(query, rcode=Rcode.REFUSED)
        try:
            qtype = DnsRecordType(query.qtype)
        except ValueError:
            return encode_response(query)
        if not _reserved:
            if self._pending_queries >= self._options.max_pending_queries:
                logger.warning(
                    "DNS query rejected server_id=%s domain=%r qtype=%s "
                    "reason=max_pending_queries active_queries=%s "
                    "max_pending_queries=%s",
                    self._server_id,
                    query.domain,
                    query.qtype,
                    self._pending_queries,
                    self._options.max_pending_queries,
                )
                return encode_response(query, rcode=Rcode.SERVFAIL)
            self._pending_queries += 1
        try:
            async with asyncio.timeout(self._options.callback_timeout):
                result = self._resolve(query.domain, qtype)
                if inspect.isawaitable(result):
                    result = await result
            if result is None:
                return encode_response(query, rcode=Rcode.NXDOMAIN)
            if isinstance(result, str):
                labels = _cname_labels(result)
                if (
                    self._upstream_dns is not None
                    and qtype in (DnsRecordType.A, DnsRecordType.AAAA)
                    and self._state not in ("closing", "closed")
                ):
                    address = await self._lookup_upstream(labels, qtype)
                    if address is not None:
                        return encode_response(
                            query, address=address, ttl=self._options.ttl, udp=_udp
                        )
                return encode_response(
                    query, cname=labels, ttl=self._options.ttl, udp=_udp
                )
            if not isinstance(result, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                raise TypeError(
                    "resolve must return an IP object, domain string or None"
                )
            address = result
            if (
                isinstance(address, ipaddress.IPv6Address)
                and address.scope_id is not None
            ):
                raise ValueError("DNS addresses cannot contain an IPv6 scope ID")
            expected_type = (
                DnsRecordType.A if address.version == 4 else DnsRecordType.AAAA
            )
            return encode_response(
                query,
                address=address.packed if qtype == expected_type else None,
                ttl=self._options.ttl,
                udp=_udp,
            )
        except Exception as exc:
            logger.log(
                failure_level(exc),
                "DNS callback failed server_id=%s domain=%r qtype=%s error_type=%s",
                self._server_id,
                query.domain,
                query.qtype,
                type(exc).__name__,
            )
            return encode_response(query, rcode=Rcode.SERVFAIL)
        finally:
            if not _reserved:
                self._pending_queries -= 1

    async def _lookup_upstream(
        self, labels: tuple[bytes, ...], qtype: DnsRecordType
    ) -> bytes | None:
        assert self._upstream_dns is not None
        loop = self._check_loop()
        identifier = secrets.randbits(16)
        query = encode_upstream_query(labels, qtype, identifier)
        family = (
            socket.AF_INET
            if ipaddress.ip_address(self._upstream_dns[0]).version == 4
            else socket.AF_INET6
        )
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as connection:
                connection.setblocking(False)
                async with asyncio.timeout(self._options.upstream_timeout):
                    # A connected UDP socket only receives this upstream's packets.
                    await loop.sock_connect(connection, self._upstream_dns)
                    await loop.sock_sendall(connection, query)
                    while True:
                        reply = await loop.sock_recv(connection, 65535)
                        if len(reply) >= 2 and int.from_bytes(reply[:2]) != identifier:
                            continue
                        address = decode_upstream_address(
                            reply, identifier=identifier, labels=labels, qtype=qtype
                        )
                        logger.debug(
                            "DNS upstream completed server_id=%s upstream=%r "
                            "alias=%r qtype=%s address_found=%s",
                            self._server_id,
                            self._upstream_dns,
                            b".".join(labels),
                            int(qtype),
                            address is not None,
                        )
                        return address
        except (OSError, TimeoutError, DnsFormatError) as exc:
            logger.warning(
                "DNS upstream failed server_id=%s upstream=%r alias=%r qtype=%s "
                "error_type=%s",
                self._server_id,
                self._upstream_dns,
                b".".join(labels),
                int(qtype),
                type(exc).__name__,
            )
            return None

    def _datagram_received(self, packet: bytes, endpoint: tuple) -> None:
        if (
            self._state != "running"
            or self._pending_queries >= self._options.max_pending_queries
        ):
            logger.log(
                logging.WARNING if self._state == "running" else logging.DEBUG,
                "DNS datagram dropped server_id=%s listener=%r peer=%r state=%s "
                "active_queries=%s max_pending_queries=%s",
                self._server_id,
                self._address,
                endpoint,
                self._state,
                self._pending_queries,
                self._options.max_pending_queries,
            )
            return
        self._pending_queries += 1
        task = self._check_loop().create_task(self._reply_datagram(packet, endpoint))
        self._udp_tasks.add(task)
        task.add_done_callback(self._datagram_done)

    async def _reply_datagram(self, packet: bytes, endpoint: tuple) -> None:
        reply = await self._answer(
            packet, _reserved=True, _udp=True, _transport="udp", _peer=endpoint
        )
        if reply is not None and self._state == "running":
            assert self._udp_transport is not None
            self._udp_transport.sendto(reply, endpoint)

    def _datagram_done(self, task: asyncio.Task) -> None:
        self._udp_tasks.discard(task)
        self._pending_queries -= 1
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled DNS datagram error", exc_info=error)

    def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if (
            self._state != "running"
            or len(self._connections) >= self._options.max_tcp_connections
        ):
            logger.log(
                logging.WARNING if self._state == "running" else logging.DEBUG,
                "DNS TCP rejected server_id=%s listener=%r peer=%r state=%s "
                "active_connections=%s max_tcp_connections=%s",
                self._server_id,
                self._address,
                writer.get_extra_info("peername"),
                self._state,
                self.active_connections,
                self._options.max_tcp_connections,
            )
            writer.transport.abort()
            return
        task = self._check_loop().create_task(self._serve_connection(reader, writer))
        self._connections[task] = writer
        task.add_done_callback(self._connection_done)

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.debug(
            "DNS TCP accepted server_id=%s listener=%r peer=%r active_connections=%s",
            self._server_id,
            self._address,
            peer,
            self.active_connections,
        )
        try:
            while self._state == "running":
                async with asyncio.timeout(self._options.tcp_idle_timeout):
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                    if size == 0:
                        return
                    packet = await reader.readexactly(size)
                reply = await self._answer(packet, _transport="tcp", _peer=peer)
                if reply is not None and self._state == "running":
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    async with asyncio.timeout(self._options.tcp_idle_timeout):
                        await writer.drain()
        except (OSError, asyncio.IncompleteReadError, TimeoutError) as exc:
            logger.debug(
                "DNS TCP ended server_id=%s peer=%r error_type=%s",
                self._server_id,
                peer,
                type(exc).__name__,
            )
        finally:
            writer.close()
            try:
                async with asyncio.timeout(self._options.tcp_idle_timeout):
                    await writer.wait_closed()
            except OSError, TimeoutError:
                writer.transport.abort()
            except asyncio.CancelledError:
                writer.transport.abort()
                raise

    def _connection_done(self, task: asyncio.Task) -> None:
        # Cancellation before the first step skips the handler's finally block.
        self._connections.pop(task).transport.abort()
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled DNS TCP error", exc_info=error)

    async def serve_forever(self) -> None:
        self._check_loop()
        if self._state != "running":
            raise RuntimeError("server is not listening")
        try:
            await self._stopped.wait()
        except asyncio.CancelledError:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        loop = self._check_loop()
        async with self._lock:
            if self._close_task is None:
                self._loop = loop
                self._state = "closing"
                self._close_task = loop.create_task(self._close(asyncio.current_task()))
            task = self._close_task
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.shield(task)
            raise

    async def _close(self, initiator: asyncio.Task | None) -> None:
        listener = self._address
        try:
            self._address = None
            if self._tcp_server is not None:
                self._tcp_server.close()
            if self._udp_transport is not None:
                self._udp_transport.close()
            tasks = (self._udp_tasks | self._connections.keys()) - {initiator}
            writers = list(self._connections.values())
            for writer in writers:
                writer.transport.abort()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers), return_exceptions=True
            )
            if self._tcp_server is not None:
                await self._tcp_server.wait_closed()
            if self._udp_transport is not None and self._udp_closed is not None:
                await self._udp_closed
        finally:
            self._state = "closed"
            self._stopped.set()
            logger.info(
                "DNS server stopped server_id=%s listener=%r active_queries=%s "
                "active_connections=%s",
                self._server_id,
                listener,
                self.active_queries,
                self.active_connections,
            )

    async def __aenter__(self) -> Self:
        self._check_loop()
        if self._state != "new":
            raise RuntimeError("server can only be started once")
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
