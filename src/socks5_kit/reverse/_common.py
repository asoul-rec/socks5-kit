"""Shared SOCKS semantics for the two reverse endpoint roles."""

import errno
import math

from ..errors import ProtocolError, RejectTarget, UpstreamRejected
from ..models import Target
from ..protocol import ReplyCode

DEFAULT_REVERSE_DOMAIN = "reverse.socks5-kit.invalid"
# Versioned payload frames, distinct from ordinary SOCKS replies. The agent
# pipelines HELLO with the local SOCKS CONNECT to provide a prompt first payload.
REGISTRATION_HELLO = b"S5KR\x01\x01"
REGISTRATION_ACK = b"S5KR\x01\x02"


def canonical_domain(value: str) -> str:
    """Normalize the reserved registration name for case-insensitive matching."""
    if not isinstance(value, str):
        raise TypeError("reverse_domain must be a domain string")
    host = Target(value, 1).host
    assert isinstance(host, str)
    return host.lower().removesuffix(".")


def failure_reply(error: Exception) -> int:
    """Preserve upstream SOCKS errors and map ordinary connect failures."""
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


def validate_grace_period(value: float) -> None:
    """Validate an optional graceful shutdown interval before changing state."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("grace_period must be a number")
    if not math.isfinite(value) or value < 0:
        raise ValueError("grace_period must be finite and nonnegative")
