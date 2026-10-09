"""Public addresses, callback contracts and TCP server options."""

import ipaddress
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Literal


class AddressType(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


type Host = ipaddress.IPv4Address | ipaddress.IPv6Address | str


def _normalize(host: Host, port: int, *, allow_zero: bool) -> tuple[Host, int]:
    if not isinstance(host, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise TypeError("host must be an IPv4Address, IPv6Address or domain string")
    minimum = 0 if allow_zero else 1
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("port must be an integer")
    if not minimum <= port <= 65535:
        raise ValueError(f"port must be in {minimum}..65535")
    if isinstance(host, str):
        host = host.encode("idna").decode("ascii")
        if not 1 <= len(host.encode("ascii")) <= 255:
            raise ValueError("domain must occupy 1..255 bytes")
        if any(ord(char) <= 32 or ord(char) == 127 for char in host):
            raise ValueError("domain must not contain spaces or control characters")
    elif isinstance(host, ipaddress.IPv6Address) and host.scope_id is not None:
        raise ValueError("SOCKS addresses cannot carry an IPv6 scope ID")
    return host, port


@dataclass(frozen=True, slots=True)
class BoundAddress:
    """A SOCKS reply address; unlike a request target, its port may be zero."""

    host: Host
    port: int

    def __post_init__(self) -> None:
        host, port = _normalize(self.host, self.port, allow_zero=True)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)

    @property
    def kind(self) -> AddressType:
        """Derive the SOCKS address type without interpreting domain strings."""
        if isinstance(self.host, ipaddress.IPv4Address):
            return AddressType.IPV4
        if isinstance(self.host, ipaddress.IPv6Address):
            return AddressType.IPV6
        return AddressType.DOMAIN


@dataclass(frozen=True, slots=True)
class Target(BoundAddress):
    """An immutable request target with an IP object or a domain string."""

    def __post_init__(self) -> None:
        host, port = _normalize(self.host, self.port, allow_zero=False)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)


@dataclass(frozen=True, slots=True)
class RewriteContext:
    transport: Literal["tcp", "udp"]
    direction: Literal["outbound", "inbound"]
    client_endpoint: tuple[str, int]
    session_id: int
    flow_id: int | None = None
    username: bytes | None = field(default=None, repr=False)
    password: bytes | None = field(default=None, repr=False)


type RewriteCallback = Callable[
    [Target, RewriteContext], Target | None | Awaitable[Target | None]
]
type ReverseCallback = Callable[
    [Target, RewriteContext], Target | None | Awaitable[Target | None]
]


@dataclass(frozen=True, slots=True)
class ServerOptions:
    handshake_timeout: float = 10.0
    callback_timeout: float = 10.0
    upstream_connect_timeout: float = 10.0
    upstream_handshake_timeout: float = 10.0
    reply_timeout: float = 5.0
    max_connections: int = 1024
    backlog: int = 128
    ipv6_only: bool = True
    splice_byte_budget: int = 256 * 1024
    splice_call_budget: int = 8

    def __post_init__(self) -> None:
        for name in (
            "handshake_timeout",
            "callback_timeout",
            "upstream_connect_timeout",
            "upstream_handshake_timeout",
            "reply_timeout",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name in (
            "max_connections",
            "backlog",
            "splice_byte_budget",
            "splice_call_budget",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if not isinstance(self.ipv6_only, bool):
            raise TypeError("ipv6_only must be a bool")
