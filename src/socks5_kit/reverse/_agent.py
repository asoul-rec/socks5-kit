"""Proactively supply single-use reverse tunnels through a local SOCKS proxy."""

import asyncio
import itertools
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Self

from .._credentials import validate_credentials
from .._io import read_address, read_exact
from .._linux.splice import SpliceRelay, ensure_supported
from .._logging import failure_level, log_event
from ..client import Socks5Client, TcpTunnel
from ..errors import ProtocolError
from ..models import AddressType, Target
from ..protocol import VERSION, Command, ReplyCode, encode_reply
from ._common import (
    REGISTRATION_ACK,
    REGISTRATION_HELLO,
    failure_reply,
    validate_grace_period,
)
from ._options import ReverseAgentOptions

logger = logging.getLogger(__name__)
_resource_ids = itertools.count(1)


@dataclass(eq=False, slots=True)
class _UserPool:
    credentials: tuple[str, str] | None = field(repr=False)
    retry_delay: float
    retry_at: float = 0.0

    @property
    def user(self) -> str | None:
        return self.credentials[0] if self.credentials is not None else None


@dataclass(slots=True)
class _Resource:
    pool: _UserPool
    state: str = "opening"


class ReverseAgent:
    """Keep a bounded pool of reverse resources registered through ``proxy``.

    ``start()`` starts background registration, without waiting for a remote
    resource to become available. Registration success from an intermediate
    proxy need not mean that the final reverse server has accepted it yet.
    A resource counts as idle only after the final server's registration ACK.
    Construction performs no I/O; lifecycle methods belong to one event loop.
    """

    def __init__(
        self,
        registration_target: Target,
        proxy: Socks5Client,
        *,
        options: ReverseAgentOptions | None = None,
        egress_proxy: Socks5Client | None = None,
        users: Sequence[None | str | tuple[str, str]] = (None,),
    ) -> None:
        if not isinstance(registration_target, Target):
            raise TypeError("registration_target must be a Target")
        if registration_target.kind != AddressType.DOMAIN:
            raise ValueError("registration_target must be a DOMAIN Target")
        if not isinstance(proxy, Socks5Client):
            raise TypeError("proxy must be a Socks5Client")
        if egress_proxy is not None and not isinstance(egress_proxy, Socks5Client):
            raise TypeError("egress_proxy must be a Socks5Client")
        if options is not None and not isinstance(options, ReverseAgentOptions):
            raise TypeError("options must be ReverseAgentOptions")
        self._registration_target = registration_target
        self._proxy = proxy
        self._egress_proxy = proxy if egress_proxy is None else egress_proxy
        self._options = options or ReverseAgentOptions()
        if not isinstance(users, Sequence) or isinstance(
            users, (str, bytes, bytearray)
        ):
            raise TypeError(
                "users must be a sequence of None, usernames or credential pairs"
            )
        if not users:
            raise ValueError("users must not be empty")
        self._pools: dict[str | None, _UserPool] = {}
        for value in users:
            credentials = validate_credentials(
                (value, "") if isinstance(value, str) else value
            )
            user = credentials[0] if credentials is not None else None
            if user in self._pools:
                raise ValueError("users must not contain duplicate usernames")
            self._pools[user] = _UserPool(
                credentials, self._options.reconnect_initial_delay
            )
        if (
            self._options.max_total_connections is not None
            and self._options.max_total_connections
            < len(self._pools) * self._options.idle_connections
        ):
            raise ValueError(
                "max_total_connections must cover all users' idle_connections"
            )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._state = "new"
        self._resources: dict[asyncio.Task, _Resource] = {}
        self._manager_task: asyncio.Task | None = None
        self._manager_error: BaseException | None = None
        self._close_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._stopped = asyncio.Event()
        self._next_pool = 0

    @property
    def connection_count(self) -> int:
        """Resources registering, waiting, connecting to a target, or relaying."""
        return len(self._resources)

    @property
    def idle_connections(self) -> int:
        """Server-ACKed streams waiting for a complete reverse CONNECT."""
        return sum(resource.state == "waiting" for resource in self._resources.values())

    @property
    def active_connections(self) -> int:
        """Resources connecting to their business target or relaying bytes."""
        return sum(resource.state == "busy" for resource in self._resources.values())

    def _user_resources(self, user: str | None) -> list[_Resource]:
        if user is not None and not isinstance(user, str):
            raise TypeError("user must be a username string or None")
        pool = self._pools.get(user)
        return [
            resource for resource in self._resources.values() if resource.pool is pool
        ]

    def idle_count(self, user: str | None = None) -> int:
        """ACK-confirmed idle resources for one local SOCKS username."""
        return sum(
            resource.state == "waiting" for resource in self._user_resources(user)
        )

    def connection_count_for(self, user: str | None = None) -> int:
        """Opening, idle and busy resources for one local SOCKS username."""
        return len(self._user_resources(user))

    def active_count(self, user: str | None = None) -> int:
        """Resources serving business requests for one local SOCKS username."""
        return sum(resource.state == "busy" for resource in self._user_resources(user))

    def _check_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("agent must be used on its original event loop")
        return loop

    def _log_event(self, level: int, event: str, **fields: object) -> None:
        log_event(logger, level, event, agent_id=id(self), **fields)

    def _log_pool(
        self, pool: _UserPool, decision: str, *, spawn_count: int = 0
    ) -> None:
        if not logger.isEnabledFor(logging.DEBUG):
            return
        fields = {
            "user": pool.user,
            "decision": decision,
            "idle": self.idle_count(pool.user),
            "opening": sum(
                resource.state == "opening"
                for resource in self._user_resources(pool.user)
            ),
            "busy": self.active_count(pool.user),
            "total": self.connection_count_for(pool.user),
            "desired_idle": self._options.idle_connections,
            "max_connections": self._options.max_connections,
        }
        if self._options.max_total_connections is not None:
            fields["global_total"] = self.connection_count
            fields["max_total_connections"] = self._options.max_total_connections
        if spawn_count:
            fields["spawn_count"] = spawn_count
        if decision == "backoff":
            fields["retry_in_ms"] = round(
                max(0.0, pool.retry_at - self._check_loop().time()) * 1000, 3
            )
        self._log_event(logging.DEBUG, "reverse_agent_pool", **fields)

    async def start(self) -> None:
        loop = self._check_loop()
        async with self._lock:
            if self._state != "new":
                raise RuntimeError("agent can only be started once")
            ensure_supported(loop)
            self._loop = loop
            self._state = "running"
            self._manager_task = loop.create_task(self._maintain_pool())
            self._manager_task.add_done_callback(self._manager_done)
            self._log_event(
                logging.INFO,
                "reverse_agent_started",
                registration_target=self._registration_target,
                proxy=(self._proxy.ip, self._proxy.port),
                egress_proxy=(self._egress_proxy.ip, self._egress_proxy.port),
                desired_idle=self._options.idle_connections,
                max_connections=self._options.max_connections,
                user_count=len(self._pools),
                max_total_connections=self._options.max_total_connections,
            )

    def _manager_done(self, task: asyncio.Task) -> None:
        if not task.cancelled():
            self._manager_error = task.exception()
        if self._manager_error is not None:
            self._log_event(
                logging.ERROR,
                "reverse_agent_manager_failed",
                error_type=type(self._manager_error).__name__,
            )
        if self._manager_error is not None and self._state == "running":
            self._state = "closing"
            self._close_task = self._check_loop().create_task(self._close(0.0, None))
        self._stopped.set()

    async def _maintain_pool(self) -> None:
        loop = self._check_loop()
        pools = tuple(self._pools.values())
        while self._state == "running":
            self._wake.clear()
            counts = {pool: {"waiting": 0, "opening": 0, "busy": 0} for pool in pools}
            for resource in self._resources.values():
                counts[resource.pool][resource.state] += 1
            spawned = False
            earliest_retry: float | None = None
            start = self._next_pool
            for offset in range(len(pools)):
                index = (start + offset) % len(pools)
                pool = pools[index]
                count = counts[pool]
                available = count["waiting"] + count["opening"]
                if available >= self._options.idle_connections:
                    decision = (
                        "idle_satisfied"
                        if count["waiting"] >= self._options.idle_connections
                        else "registration_in_flight"
                    )
                    self._log_pool(pool, decision)
                    continue
                if sum(count.values()) >= self._options.max_connections:
                    self._log_pool(pool, "capacity_full")
                    continue
                if (
                    self._options.max_total_connections is not None
                    and self.connection_count >= self._options.max_total_connections
                ):
                    self._log_pool(pool, "global_capacity_full")
                    continue
                retrying = pool.retry_at > 0
                if retrying and count["opening"]:
                    self._log_pool(pool, "probe_in_flight")
                    continue
                if pool.retry_at > loop.time():
                    self._log_pool(pool, "backoff")
                    earliest_retry = (
                        pool.retry_at
                        if earliest_retry is None
                        else min(earliest_retry, pool.retry_at)
                    )
                    continue
                self._log_pool(pool, "probe" if retrying else "refill", spawn_count=1)
                task = loop.create_task(self._serve_resource(pool))
                # Reserve both user and global capacity before the task starts.
                self._resources[task] = _Resource(pool)
                task.add_done_callback(self._resource_done)
                # One launch per group per round keeps the shared budget fair.
                self._next_pool = (index + 1) % len(pools)
                spawned = True
            if spawned:
                continue
            if earliest_retry is None:
                await self._wake.wait()
            else:
                try:
                    async with asyncio.timeout(max(0.0, earliest_retry - loop.time())):
                        await self._wake.wait()
                except TimeoutError:
                    pass

    def _resource_done(self, task: asyncio.Task) -> None:
        self._resources.pop(task, None)
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled reverse agent resource error", exc_info=error)
        self._wake.set()

    def _registration_failed(self, pool: _UserPool) -> None:
        pool.retry_at = self._check_loop().time() + pool.retry_delay
        pool.retry_delay = min(self._options.reconnect_max_delay, pool.retry_delay * 2)
        self._log_event(
            logging.INFO,
            "reverse_agent_retry_scheduled",
            user=pool.user,
            retry_in_ms=round(
                max(0.0, pool.retry_at - self._check_loop().time()) * 1000, 3
            ),
        )
        self._wake.set()

    async def _serve_resource(self, pool: _UserPool) -> None:
        task = asyncio.current_task()
        assert task is not None
        carrier: TcpTunnel | None = None
        destination: TcpTunnel | None = None
        relay: SpliceRelay | None = None
        request_started = reply_started = busy = False
        loop = self._check_loop()
        resource_id = next(_resource_ids)
        started = loop.time()
        stage = "registration_proxy"
        target = None
        outcome = "closed"
        try:
            self._log_event(
                logging.DEBUG,
                "reverse_agent_registration_started",
                resource_id=resource_id,
                user=pool.user,
            )
            credentials = (
                {} if pool.credentials is None else {"credentials": pool.credentials}
            )
            carrier = await self._proxy.connect(
                self._registration_target,
                initial_data=REGISTRATION_HELLO,
                **credentials,
            )
            if self._state != "running":
                return
            self._log_event(
                logging.DEBUG,
                "reverse_agent_registration_proxy_connected",
                resource_id=resource_id,
                user=pool.user,
                elapsed_ms=round((loop.time() - started) * 1000, 3),
            )
            stage = "registration_ack"
            async with asyncio.timeout(self._options.registration_timeout):
                acknowledgement = await read_exact(
                    carrier.socket, len(REGISTRATION_ACK)
                )
                if acknowledgement != REGISTRATION_ACK:
                    raise ProtocolError("invalid reverse registration acknowledgement")
            if self._state != "running":
                return
            self._resources[task].state = "waiting"
            pool.retry_delay = self._options.reconnect_initial_delay
            pool.retry_at = 0.0
            self._log_event(
                logging.INFO,
                "reverse_agent_registered",
                resource_id=resource_id,
                user=pool.user,
                elapsed_ms=round((loop.time() - started) * 1000, 3),
            )
            self._wake.set()
            # No timeout while idle: the carrier has no heartbeat frame, and a
            # slow or unused service should not churn healthy idle resources.
            stage = "idle"
            waiting = loop.time()
            first = await loop.sock_recv(carrier.socket, 1)
            if not first:
                self._log_event(
                    logging.INFO,
                    "reverse_agent_idle_disconnected",
                    resource_id=resource_id,
                    user=pool.user,
                    idle_ms=round((loop.time() - waiting) * 1000, 3),
                )
                self._registration_failed(pool)
                return
            request_started = True
            stage = "reverse_connect"
            async with asyncio.timeout(self._options.request_timeout):
                command, _reserved = await read_exact(carrier.socket, 2)
                if first[0] != VERSION:
                    raise ProtocolError("invalid reverse SOCKS request version")
                address = await read_address(carrier.socket)
                if command != Command.CONNECT:
                    raise ProtocolError(
                        "only TCP CONNECT is implemented",
                        ReplyCode.COMMAND_NOT_SUPPORTED,
                    )
                target = Target(address.host, address.port)
            self._resources[task].state = "busy"
            busy = True
            self._log_event(
                logging.INFO,
                "reverse_agent_business_requested",
                resource_id=resource_id,
                user=pool.user,
                target=target,
            )
            # Refill as soon as a complete request consumes this resource, in
            # parallel with the potentially slow destination connection. Only
            # a registration ACK restores normal refill after a failure.
            self._wake.set()
            connecting = loop.time()
            stage = "egress_connect"
            destination, relay = await self._egress_proxy._connect_pipelined(
                target,
                carrier.socket,
                **credentials,
                byte_budget=self._options.splice_byte_budget,
                call_budget=self._options.splice_call_budget,
            )
            self._log_event(
                logging.INFO,
                "reverse_agent_target_connected",
                resource_id=resource_id,
                user=pool.user,
                target=target,
                elapsed_ms=round((loop.time() - connecting) * 1000, 3),
            )
            reply_started = True
            stage = "reverse_reply"
            async with asyncio.timeout(self._options.reply_timeout):
                await loop.sock_sendall(
                    carrier.socket,
                    encode_reply(ReplyCode.SUCCESS, destination.bound_address),
                )
            stage = "relay"
            self._log_event(
                logging.DEBUG,
                "reverse_agent_relay_started",
                resource_id=resource_id,
                user=pool.user,
                target=target,
            )
            relay.start_reverse()
            await relay.wait()
            outcome = "completed"
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except Exception as exc:
            outcome = "failed"
            level = failure_level(exc)
            if stage == "relay" and isinstance(exc, OSError):
                level = logging.INFO
            elif stage == "reverse_connect" and isinstance(exc, ValueError):
                level = logging.WARNING
            self._log_event(
                level,
                "reverse_agent_resource_failed",
                resource_id=resource_id,
                user=pool.user,
                target=target,
                stage=stage,
                error_type=type(exc).__name__,
                elapsed_ms=round((loop.time() - started) * 1000, 3),
            )
            if not busy:
                self._registration_failed(pool)
            if carrier is not None and request_started and not reply_started:
                try:
                    async with asyncio.timeout(self._options.reply_timeout):
                        await loop.sock_sendall(
                            carrier.socket, encode_reply(failure_reply(exc))
                        )
                except OSError, TimeoutError:
                    pass
        finally:
            if relay is not None:
                relay.close()
            if destination is not None:
                destination.close()
            if carrier is not None:
                carrier.close()
            self._log_event(
                logging.DEBUG,
                "reverse_agent_resource_closed",
                resource_id=resource_id,
                user=pool.user,
                target=target,
                stage=stage,
                reason=outcome,
                elapsed_ms=round((loop.time() - started) * 1000, 3),
            )

    async def serve_forever(self) -> None:
        self._check_loop()
        if self._state != "running":
            raise RuntimeError("start the agent before serve_forever")
        try:
            await self._stopped.wait()
            if self._manager_error is not None:
                raise self._manager_error
        finally:
            await self.aclose()

    async def aclose(self, grace_period: float = 0.0) -> None:
        self._check_loop()
        validate_grace_period(grace_period)
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
            await asyncio.shield(closing)
            raise

    async def _close(self, grace_period: float, initiator: asyncio.Task | None) -> None:
        try:
            if self._manager_task is not None:
                self._manager_task.cancel()
                await asyncio.gather(self._manager_task, return_exceptions=True)
            idle = {
                task
                for task, resource in self._resources.items()
                if resource.state != "busy" and task is not initiator
            }
            for task in idle:
                task.cancel()
            if idle:
                await asyncio.gather(*idle, return_exceptions=True)
            busy = set(self._resources) - {initiator}
            if grace_period and busy:
                await asyncio.wait(busy, timeout=grace_period)
        finally:
            pending = set(self._resources) - {initiator}
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            self._state = "closed"
            self._stopped.set()
            self._log_event(logging.INFO, "reverse_agent_stopped")

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
