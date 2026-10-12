"""SOCKS5 ingress and randomly selected, single-use reverse resources."""

import asyncio
import functools
import logging
import random
import socket
from collections import OrderedDict
from dataclasses import dataclass
from typing import Self

from .._io import negotiate_server, read_exact, read_reply, read_request
from .._linux.splice import SpliceRelay, ensure_supported
from ..errors import ProtocolError
from ..models import Target
from ..protocol import Command, ReplyCode, encode_connect, encode_reply
from ._common import (
    DEFAULT_REVERSE_DOMAIN,
    REGISTRATION_ACK,
    REGISTRATION_HELLO,
    canonical_domain,
    failure_reply,
    validate_grace_period,
)
from ._options import ReverseServerOptions

logger = logging.getLogger(__name__)
type User = bytes | None


@dataclass(eq=False, slots=True)
class _Resource:
    socket: socket.socket
    user: User
    done: asyncio.Future[None]
    registration_task: asyncio.Task | None = None
    state: str = "registering"
    index: int | None = None
    watching: bool = False
    timer: asyncio.TimerHandle | None = None


@dataclass(eq=False, slots=True)
class _Pending:
    user: User
    ready: asyncio.Future[_Resource]
    resource: _Resource | None = None
    queued: bool = True


class ReverseServer:
    """Register reverse streams or dispatch business CONNECTs by raw username.

    Construct without I/O, then start on one asyncio loop. Resources are chosen
    uniformly at random within a username's idle pool and are never reused.
    The reserved registration domain matches all ports, case-insensitively.
    """

    def __init__(
        self,
        registration_domain: str = DEFAULT_REVERSE_DOMAIN,
        *,
        options: ReverseServerOptions | None = None,
    ) -> None:
        self._registration_domain = canonical_domain(registration_domain)
        if options is not None and not isinstance(options, ReverseServerOptions):
            raise TypeError("options must be ReverseServerOptions")
        self._options = options or ReverseServerOptions()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task | None = None
        self._sessions: set[asyncio.Task] = set()
        self._resources: set[_Resource] = set()
        self._pools: dict[User, list[_Resource]] = {}
        self._resource_counts: dict[User, int] = {}
        self._business_counts: dict[User, int] = {}
        self._business_count = 0
        self._slots_in_use = 0
        self._pending: dict[User, OrderedDict[_Pending, None]] = {}
        self._pending_count = 0
        self._lock = asyncio.Lock()
        self._stopped = asyncio.Event()
        self._state = "new"
        self._accept_error: BaseException | None = None
        self._close_task: asyncio.Task | None = None

    @property
    def registration_domain(self) -> str:
        return self._registration_domain

    @property
    def address(self) -> tuple[str, int]:
        if self._listener is None:
            raise RuntimeError("server is not listening")
        address = self._listener.getsockname()
        return address[0], address[1]

    @property
    def active_connections(self) -> int:
        """Accepted sockets, including handshakes, idle resources and business."""
        return len(self._sessions)

    @property
    def resource_count(self) -> int:
        """Reserved, idle and claimed resources, including those in transfer."""
        return len(self._resources)

    @property
    def idle_connections(self) -> int:
        return sum(map(len, self._pools.values()))

    @property
    def pending_connections(self) -> int:
        """Business requests queued while their exact username has no resource."""
        return self._pending_count

    @property
    def business_connections(self) -> int:
        """Admitted business requests: queued, connecting their target or relaying."""
        return self._business_count

    @property
    def slots_in_use(self) -> int:
        """Global resource quota usage, summed over independently owned user slots."""
        return self._slots_in_use

    def slot_count(self, user: User = None) -> int:
        """Quota slots for this exact user: max(registrations, business requests)."""
        if user is not None and not isinstance(user, bytes):
            raise TypeError("user must be bytes or None")
        return max(
            self._resource_counts.get(user, 0), self._business_counts.get(user, 0)
        )

    def idle_count(self, user: User = None) -> int:
        """Count idle resources for this exact user; None selects the default."""
        if user is not None and not isinstance(user, bytes):
            raise TypeError("user must be bytes or None")
        return len(self._pools.get(user, ()))

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

    async def _accept_loop(self) -> None:
        assert self._loop is not None and self._listener is not None
        while True:
            connection, _peer = await self._loop.sock_accept(self._listener)
            if len(self._sessions) >= self._options.max_connections:
                connection.close()
                continue
            try:
                connection.setblocking(False)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                task = self._loop.create_task(self._serve_connection(connection))
            except BaseException:
                connection.close()
                raise
            self._sessions.add(task)
            task.add_done_callback(functools.partial(self._session_done, connection))

    def _accept_done(self, task: asyncio.Task) -> None:
        if not task.cancelled():
            self._accept_error = task.exception()
        self._stopped.set()
        if self._accept_error is not None and self._state == "running":
            self._state = "closing"
            self._close_task = self._check_loop().create_task(self._close(0.0, None))

    def _session_done(self, connection: socket.socket, task: asyncio.Task) -> None:
        # Also closes tasks cancelled before their coroutine first runs.
        connection.close()
        self._sessions.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled reverse session error", exc_info=error)

    def _check_slot_limit(self, user: User, registrations: int, business: int) -> int:
        slots = max(registrations, business)
        added = slots - self.slot_count(user)
        limit = self._options.max_resources_per_user
        if (limit is not None and slots > limit) or (
            self._slots_in_use + added > self._options.max_resources
        ):
            raise ProtocolError("reverse resource slot limit reached")
        return added

    def _admit_business(self, user: User) -> None:
        count = self._business_counts.get(user, 0)
        added = self._check_slot_limit(
            user, self._resource_counts.get(user, 0), count + 1
        )
        self._business_counts[user] = count + 1
        self._business_count += 1
        self._slots_in_use += added

    def _release_business(self, user: User) -> None:
        before = self.slot_count(user)
        remaining = self._business_counts[user] - 1
        if remaining:
            self._business_counts[user] = remaining
        else:
            del self._business_counts[user]
        self._business_count -= 1
        self._slots_in_use += self.slot_count(user) - before

    def _reserve(self, connection: socket.socket, user: User) -> _Resource:
        count = self._resource_counts.get(user, 0)
        added = self._check_slot_limit(
            user, count + 1, self._business_counts.get(user, 0)
        )
        resource = _Resource(connection, user, self._check_loop().create_future())
        self._resources.add(resource)
        self._resource_counts[user] = count + 1
        self._slots_in_use += added
        return resource

    def _publish(self, resource: _Resource) -> None:
        pool = self._pools.setdefault(resource.user, [])
        resource.index = len(pool)
        resource.state = "idle"
        pool.append(resource)
        loop = self._check_loop()
        loop.add_reader(resource.socket.fileno(), self._idle_readable, resource)
        resource.watching = True
        if self._options.idle_timeout is not None:
            resource.timer = loop.call_later(
                self._options.idle_timeout, self._retire, resource
            )
        self._dispatch_pending(resource.user)

    def _remove_pending(self, pending: _Pending) -> None:
        if not pending.queued:
            return
        queue = self._pending[pending.user]
        del queue[pending]
        if not queue:
            del self._pending[pending.user]
        pending.queued = False
        self._pending_count -= 1

    def _dispatch_pending(self, user: User) -> None:
        while queue := self._pending.get(user):
            pending = next(iter(queue))
            if pending.ready.done():
                self._remove_pending(pending)
                continue
            resource = self._take(user)
            if resource is None:
                return
            self._remove_pending(pending)
            # Reserve for the oldest request before waking it, so a newer
            # request cannot steal the resource. The pending object also owns
            # it until the awaiting coroutine actually resumes.
            pending.resource = resource
            pending.ready.set_result(resource)

    async def _wait_for_resource(self, user: User) -> _Resource:
        if resource := self._take(user):
            return resource
        # Waiting requests retain accepted sockets. Leave an admission slot
        # when only waiters remain so a new registration can replenish them.
        limit = min(
            self._options.max_pending_connections, self._options.max_connections - 1
        )
        if self._pending_count >= limit:
            raise ProtocolError("reverse request queue is full")
        pending = _Pending(user, self._check_loop().create_future())
        self._pending.setdefault(user, OrderedDict())[pending] = None
        self._pending_count += 1
        try:
            async with asyncio.timeout(self._options.queue_timeout):
                return await pending.ready
        except BaseException:
            # Cancellation/timeout can race with delivery after the resource
            # was removed from the idle pool but before this task resumed.
            if pending.resource is not None:
                self._retire(pending.resource)
            raise
        finally:
            self._remove_pending(pending)

    def _remove_idle(self, resource: _Resource) -> None:
        if resource.index is not None:
            pool = self._pools[resource.user]
            last = pool.pop()
            if last is not resource:
                pool[resource.index] = last
                last.index = resource.index
            resource.index = None
            if not pool:
                del self._pools[resource.user]
        if resource.watching:
            assert self._loop is not None
            self._loop.remove_reader(resource.socket.fileno())
            resource.watching = False
        if resource.timer is not None:
            resource.timer.cancel()
            resource.timer = None

    def _idle_readable(self, resource: _Resource) -> None:
        if resource.state != "idle":
            return
        try:
            resource.socket.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            return
        except OSError:
            pass
        # EOF, reset or unsolicited bytes: no Agent data is valid before CONNECT.
        self._retire(resource)

    def _take(self, user: User) -> _Resource | None:
        while pool := self._pools.get(user):
            resource = pool[random.randrange(len(pool))]
            self._remove_idle(resource)
            # A ready EOF callback may not have run yet. No bytes are consumed.
            try:
                resource.socket.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                resource.state = "claimed"
                return resource
            except OSError:
                pass
            self._retire(resource)
        return None

    def _retire(self, resource: _Resource) -> None:
        if resource.state == "closed":
            return
        self._remove_idle(resource)
        resource.state = "closed"
        resource.socket.close()
        self._resources.discard(resource)
        before = self.slot_count(resource.user)
        remaining = self._resource_counts[resource.user] - 1
        if remaining:
            self._resource_counts[resource.user] = remaining
        else:
            del self._resource_counts[resource.user]
        self._slots_in_use += self.slot_count(resource.user) - before
        if not resource.done.done():
            resource.done.set_result(None)

    async def _serve_connection(self, connection: socket.socket) -> None:
        negotiated = reply_started = False
        business_admitted = False
        resource: _Resource | None = None
        relay: SpliceRelay | None = None
        try:
            async with asyncio.timeout(self._options.handshake_timeout):
                credentials = await negotiate_server(connection)
                if credentials is None:
                    return
                user, _password = credentials
                negotiated = True
                command, address = await read_request(connection)
                if command != Command.CONNECT:
                    raise ProtocolError(
                        "only TCP CONNECT is implemented",
                        ReplyCode.COMMAND_NOT_SUPPORTED,
                    )
                target = Target(address.host, address.port)
            if self._state != "running":
                return
            loop = self._check_loop()
            if (
                isinstance(target.host, str)
                and canonical_domain(target.host) == self.registration_domain
            ):
                resource = self._reserve(connection, user)
                resource.registration_task = asyncio.current_task()
                reply_started = True
                async with asyncio.timeout(self._options.reply_timeout):
                    await loop.sock_sendall(connection, encode_reply(ReplyCode.SUCCESS))
                async with asyncio.timeout(self._options.registration_timeout):
                    hello = await read_exact(connection, len(REGISTRATION_HELLO))
                    if hello != REGISTRATION_HELLO:
                        raise ProtocolError("invalid reverse registration hello")
                if self._state != "running":
                    return
                async with asyncio.timeout(self._options.reply_timeout):
                    await loop.sock_sendall(connection, REGISTRATION_ACK)
                if self._state != "running":
                    return
                self._publish(resource)
                # The registration handler owns the socket until its one use ends.
                # Claiming removes its idle FD watcher before any business I/O.
                await resource.done
            else:
                self._admit_business(user)
                business_admitted = True
                resource = await self._wait_for_resource(user)
                async with asyncio.timeout(self._options.request_timeout):
                    await loop.sock_sendall(resource.socket, encode_connect(target))
                    bound = await read_reply(resource.socket)
                relay = SpliceRelay(
                    connection,
                    resource.socket,
                    byte_budget=self._options.splice_byte_budget,
                    call_budget=self._options.splice_call_budget,
                )
                reply_started = True
                async with asyncio.timeout(self._options.reply_timeout):
                    await loop.sock_sendall(
                        connection, encode_reply(ReplyCode.SUCCESS, bound)
                    )
                await relay.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("reverse session ended: %s", exc)
            if negotiated and not reply_started:
                try:
                    async with asyncio.timeout(self._options.reply_timeout):
                        await self._check_loop().sock_sendall(
                            connection, encode_reply(failure_reply(exc))
                        )
                except OSError, TimeoutError:
                    pass
        finally:
            if relay is not None:
                relay.close()
            if resource is not None:
                self._retire(resource)
            connection.close()
            if business_admitted:
                self._release_business(user)

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
        loop = self._check_loop()
        validate_grace_period(grace_period)
        async with self._lock:
            if self._state == "closed":
                return
            if self._close_task is None:
                self._state = "closing"
                self._close_task = loop.create_task(
                    self._close(grace_period, asyncio.current_task())
                )
            closing = self._close_task
        try:
            await asyncio.shield(closing)
        except asyncio.CancelledError:
            await asyncio.shield(closing)
            raise

    async def _close(self, grace_period: float, initiator: asyncio.Task | None) -> None:
        try:
            if self._accept_task is not None:
                self._accept_task.cancel()
                await asyncio.gather(self._accept_task, return_exceptions=True)
            if self._listener is not None:
                self._listener.close()
                self._listener = None
            for queue in tuple(self._pending.values()):
                for pending in tuple(queue):
                    self._remove_pending(pending)
                    pending.ready.cancel()
            for resource in tuple(self._resources):
                if resource.state != "claimed":
                    if (
                        resource.registration_task is not None
                        and resource.registration_task is not initiator
                    ):
                        # Closing a raw socket alone does not wake a pending
                        # sock_recv waiting for HELLO. Registration and idle
                        # streams are closed immediately, outside relay grace.
                        resource.registration_task.cancel()
                    self._retire(resource)
            pending = set(self._sessions) - {initiator}
            if grace_period and pending:
                await asyncio.wait(pending, timeout=grace_period)
        finally:
            pending = set(self._sessions) - {initiator}
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for resource in tuple(self._resources):
                self._retire(resource)
            self._sessions.difference_update(pending)
            self._state = "closed"
            self._stopped.set()

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
