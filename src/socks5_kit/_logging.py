"""Render only supplied event fields, preserving the same structured extras."""

import logging

from .errors import ProtocolError, RejectTarget, UpstreamRejected
from .protocol import ReplyCode


def failure_level(error: Exception) -> int:
    """Separate policy refusals, recoverable I/O/protocol faults, and coding errors."""
    if isinstance(error, RejectTarget):
        return logging.INFO
    if isinstance(error, ProtocolError) and error.reply in (
        ReplyCode.NOT_ALLOWED,
        ReplyCode.COMMAND_NOT_SUPPORTED,
    ):
        return logging.INFO
    if isinstance(error, (ProtocolError, UpstreamRejected, OSError, TimeoutError)):
        return logging.WARNING
    return logging.ERROR


def log_event(logger: logging.Logger, level: int, event: str, **fields: object) -> None:
    if not logger.isEnabledFor(level):
        return
    # None is meaningful for the default SOCKS user; other absent context is omitted.
    fields = {
        key: value
        for key, value in fields.items()
        if value is not None or key == "user"
    }
    message = "event=%s" + "".join(f" {key}=%r" for key in fields)
    logger.log(
        level, message, event, *fields.values(), extra={"event": event, **fields}
    )
