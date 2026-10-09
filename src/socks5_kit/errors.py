"""Errors callers may handle without inspecting wire messages."""


class Socks5Error(Exception):
    """Base protocol/client error."""


class ProtocolError(Socks5Error):
    def __init__(self, message: str, reply: int = 1) -> None:
        super().__init__(message)
        self.reply = reply


class RejectTarget(Socks5Error):
    """A callback's explicit policy refusal; returning None has the same effect."""


class UpstreamRejected(Socks5Error):
    def __init__(self, reply: int) -> None:
        super().__init__(f"upstream rejected request with REP=0x{reply:02x}")
        self.reply = reply


class PlatformError(RuntimeError):
    """The event loop or platform cannot provide the Linux data path."""
