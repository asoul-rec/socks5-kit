"""Proactively supply single-use reverse tunnels through a local SOCKS proxy."""

import asyncio
import logging
from typing import Self

from .._io import read_address, read_exact
from .._linux.splice import SpliceRelay, ensure_supported
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
        self._loop: asyncio.AbstractEventLoop | None = None
        self._state = "new"
        self._resources: dict[asyncio.Task, str] = {}
        self._manager_task: asyncio.Task | None = None
        self._manager_error: BaseException | None = None
        self._close_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._stopped = asyncio.Event()
        self._retry_at = 0.0
        self._retry_delay = self._options.reconnect_initial_delay

    @property
    def connection_count(self) -> int:
        """Resources registering, waiting, connecting to a target, or relaying."""
        return len(self._resources)

    @property
    def idle_connections(self) -> int:
        """Server-ACKed streams waiting for a complete reverse CONNECT."""
        return sum(state == "waiting" for state in self._resources.values())

    @property
    def active_connections(self) -> int:
        """Resources connecting to their business target or relaying bytes."""
        return sum(state == "busy" for state in self._resources.values())

    def _check_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("agent must be used on its original event loop")
        return loop

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

    def _manager_done(self, task: asyncio.Task) -> None:
        if not task.cancelled():
            self._manager_error = task.exception()
        if self._manager_error is not None and self._state == "running":
            self._state = "closing"
            self._close_task = self._check_loop().create_task(self._close(0.0, None))
        self._stopped.set()

    async def _maintain_pool(self) -> None:
        loop = self._check_loop()
        while self._state == "running":
            self._wake.clear()
            available = sum(state != "busy" for state in self._resources.values())
            needed = min(
                self._options.idle_connections - available,
                self._options.max_connections - self.connection_count,
            )
            if needed > 0:
                delay = self._retry_at - loop.time()
                if delay <= 0:
                    for _ in range(needed):
                        task = loop.create_task(self._serve_resource())
                        # Reserve capacity before the coroutine can start. A task
                        # cancelled before entry owns no socket or pipe yet.
                        self._resources[task] = "opening"
                        task.add_done_callback(self._resource_done)
                    continue
                try:
                    async with asyncio.timeout(delay):
                        await self._wake.wait()
                except TimeoutError:
                    pass
            else:
                await self._wake.wait()

    def _resource_done(self, task: asyncio.Task) -> None:
        self._resources.pop(task, None)
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("unhandled reverse agent resource error", exc_info=error)
        self._wake.set()

    def _registration_failed(self) -> None:
        self._retry_at = self._check_loop().time() + self._retry_delay
        self._retry_delay = min(
            self._options.reconnect_max_delay, self._retry_delay * 2
        )
        self._wake.set()

    async def _serve_resource(self) -> None:
        task = asyncio.current_task()
        assert task is not None
        carrier: TcpTunnel | None = None
        destination: TcpTunnel | None = None
        relay: SpliceRelay | None = None
        request_started = reply_started = busy = False
        loop = self._check_loop()
        try:
            carrier = await self._proxy.connect(
                self._registration_target, initial_data=REGISTRATION_HELLO
            )
            if self._state != "running":
                return
            async with asyncio.timeout(self._options.registration_timeout):
                acknowledgement = await read_exact(
                    carrier.socket, len(REGISTRATION_ACK)
                )
                if acknowledgement != REGISTRATION_ACK:
                    raise ProtocolError("invalid reverse registration acknowledgement")
            if self._state != "running":
                return
            self._resources[task] = "waiting"
            self._retry_delay = self._options.reconnect_initial_delay
            self._retry_at = 0.0
            self._wake.set()
            # No timeout while idle: the carrier has no heartbeat frame, and a
            # slow or unused service should not churn healthy idle resources.
            first = await loop.sock_recv(carrier.socket, 1)
            if not first:
                self._registration_failed()
                return
            request_started = True
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
            self._resources[task] = "busy"
            busy = True
            self._retry_delay = self._options.reconnect_initial_delay
            self._retry_at = 0.0
            # Refill as soon as a complete request consumes this resource, in
            # parallel with the potentially slow destination connection.
            self._wake.set()
            destination = await self._egress_proxy.connect(target)
            relay = SpliceRelay(
                carrier.socket,
                destination.socket,
                byte_budget=self._options.splice_byte_budget,
                call_budget=self._options.splice_call_budget,
            )
            reply_started = True
            async with asyncio.timeout(self._options.reply_timeout):
                await loop.sock_sendall(
                    carrier.socket,
                    encode_reply(ReplyCode.SUCCESS, destination.bound_address),
                )
            await relay.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("reverse agent resource ended: %s", exc)
            if not busy:
                self._registration_failed()
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
                for task, state in self._resources.items()
                if state != "busy" and task is not initiator
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

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
