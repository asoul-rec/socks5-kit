"""SOCKS5 target rewriting, client components and callback-backed DNS."""

from .client import Socks5Client, TcpTunnel
from .dns import DnsOptions, DnsRecordType, DnsResolver, DnsServer
from .errors import (
    PlatformError,
    ProtocolError,
    RejectTarget,
    Socks5Error,
    UpstreamRejected,
)
from .models import (
    AddressType,
    BoundAddress,
    ReverseCallback,
    RewriteCallback,
    RewriteContext,
    ServerOptions,
    Target,
)
from .server import Socks5RewriteServer

__all__ = [
    "AddressType",
    "BoundAddress",
    "DnsOptions",
    "DnsRecordType",
    "DnsResolver",
    "DnsServer",
    "PlatformError",
    "ProtocolError",
    "RejectTarget",
    "ReverseCallback",
    "RewriteCallback",
    "RewriteContext",
    "ServerOptions",
    "Socks5Client",
    "Socks5Error",
    "Socks5RewriteServer",
    "Target",
    "TcpTunnel",
    "UpstreamRejected",
]
