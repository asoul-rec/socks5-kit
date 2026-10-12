"""Resource and timeout limits for reverse TCP endpoints."""

import math
from dataclasses import dataclass


def _positive_number(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")


def _positive_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class ReverseServerOptions:
    """Limits shared by registration and business SOCKS connections.

    ``idle_timeout=None`` retains registered resources until they are claimed
    or disconnected. Each user's resource quota is the larger of registrations
    (reserved, idle and claimed until closed) and admitted business requests
    (queued, connecting and relaying). The global quota sums these user slots.
    The total connection limit also counts the
    accepted business sockets, queued requests and handshakes. An empty pool
    queues up to ``max_pending_connections`` requests for ``queue_timeout``;
    zero pending capacity disables waiting.
    """

    handshake_timeout: float = 10.0
    request_timeout: float = 10.0
    reply_timeout: float = 5.0
    max_connections: int = 2048
    max_resources: int = 1024
    max_resources_per_user: int | None = None
    idle_timeout: float | None = None
    backlog: int = 128
    ipv6_only: bool = True
    splice_byte_budget: int = 256 * 1024
    splice_call_budget: int = 8
    registration_timeout: float = 10.0
    queue_timeout: float = 10.0
    max_pending_connections: int = 1024

    def __post_init__(self) -> None:
        for name in (
            "handshake_timeout",
            "registration_timeout",
            "queue_timeout",
            "request_timeout",
            "reply_timeout",
        ):
            _positive_number(name, getattr(self, name))
        if self.idle_timeout is not None:
            _positive_number("idle_timeout", self.idle_timeout)
        for name in (
            "max_connections",
            "max_resources",
            "backlog",
            "splice_byte_budget",
            "splice_call_budget",
        ):
            _positive_integer(name, getattr(self, name))
        if self.max_resources_per_user is not None:
            _positive_integer("max_resources_per_user", self.max_resources_per_user)
        if not isinstance(self.ipv6_only, bool):
            raise TypeError("ipv6_only must be a bool")
        if isinstance(self.max_pending_connections, bool) or not isinstance(
            self.max_pending_connections, int
        ):
            raise TypeError("max_pending_connections must be an integer")
        if self.max_pending_connections < 0:
            raise ValueError("max_pending_connections must be nonnegative")


@dataclass(frozen=True, slots=True)
class ReverseAgentOptions:
    """Idle pool target, total connection budget, and reconnect policy.

    The connection budget includes resources being established, waiting for a
    request, connecting their target, and forwarding application data.
    """

    idle_connections: int = 1
    max_connections: int = 64
    request_timeout: float = 10.0
    reply_timeout: float = 5.0
    reconnect_initial_delay: float = 0.1
    reconnect_max_delay: float = 5.0
    splice_byte_budget: int = 256 * 1024
    splice_call_budget: int = 8
    registration_timeout: float = 10.0

    def __post_init__(self) -> None:
        for name in (
            "registration_timeout",
            "request_timeout",
            "reply_timeout",
            "reconnect_initial_delay",
            "reconnect_max_delay",
        ):
            _positive_number(name, getattr(self, name))
        for name in (
            "idle_connections",
            "max_connections",
            "splice_byte_budget",
            "splice_call_budget",
        ):
            _positive_integer(name, getattr(self, name))
        if self.idle_connections > self.max_connections:
            raise ValueError("idle_connections must not exceed max_connections")
        if self.reconnect_max_delay < self.reconnect_initial_delay:
            raise ValueError("reconnect_max_delay must not be less than initial delay")
