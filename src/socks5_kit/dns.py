"""Callback DNS server with optional upstream lookup of A/AAAA alias targets."""

import asyncio
import inspect
import ipaddress
import logging
import math
import secrets
import socket
import struct
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

__all__ = ["DnsOptions", "DnsRecordType", "DnsResolver", "DnsServer"]

logger = logging.getLogger(__name__)


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
        logger.debug("DNS datagram error: %s", exc)

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
            logger.debug("DNS callback for %s failed: %s", query.domain, exc)
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
                        return decode_upstream_address(
                            reply, identifier=identifier, labels=labels, qtype=qtype
                        )
        except (OSError, TimeoutError, DnsFormatError) as exc:
            logger.debug("DNS upstream lookup failed: %s", exc)
            return None

    def _datagram_received(self, packet: bytes, endpoint: tuple) -> None:
        if (
            self._state != "running"
            or self._pending_queries >= self._options.max_pending_queries
        ):
            return
        self._pending_queries += 1
        task = self._check_loop().create_task(self._reply_datagram(packet, endpoint))
        self._udp_tasks.add(task)
        task.add_done_callback(self._datagram_done)

    async def _reply_datagram(self, packet: bytes, endpoint: tuple) -> None:
        reply = await self._answer(packet, _reserved=True, _udp=True)
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
            writer.transport.abort()
            return
        task = self._check_loop().create_task(self._serve_connection(reader, writer))
        self._connections[task] = writer
        task.add_done_callback(self._connection_done)

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while self._state == "running":
                async with asyncio.timeout(self._options.tcp_idle_timeout):
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                    if size == 0:
                        return
                    packet = await reader.readexactly(size)
                reply = await self._answer(packet)
                if reply is not None and self._state == "running":
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    async with asyncio.timeout(self._options.tcp_idle_timeout):
                        await writer.drain()
        except OSError, asyncio.IncompleteReadError, TimeoutError:
            pass
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

    async def __aenter__(self) -> Self:
        self._check_loop()
        if self._state != "new":
            raise RuntimeError("server can only be started once")
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
