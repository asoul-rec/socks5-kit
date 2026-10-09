"""Pure SOCKS5 address/message codecs; socket I/O lives in _io."""

import ipaddress
import struct
from enum import IntEnum

from .errors import ProtocolError
from .models import AddressType, BoundAddress, Target

VERSION = 5
NO_AUTH = 0
USERNAME_PASSWORD = 2
NO_ACCEPTABLE_METHOD = 255


class Command(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class ReplyCode(IntEnum):
    SUCCESS = 0
    GENERAL_FAILURE = 1
    NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_NOT_SUPPORTED = 8


def encode_address(address: BoundAddress) -> bytes:
    if isinstance(address.host, str):
        encoded = address.host.encode("ascii")
        host = bytes([len(encoded)]) + encoded
    else:
        host = address.host.packed
    return bytes([address.kind]) + host + struct.pack("!H", address.port)


def decode_address(data: bytes) -> tuple[BoundAddress, int]:
    """Decode one address and report consumed bytes, leaving following data alone."""
    if not data:
        raise ProtocolError("missing address type")
    try:
        kind = AddressType(data[0])
    except ValueError as exc:
        raise ProtocolError(
            "unsupported address type", ReplyCode.ADDRESS_NOT_SUPPORTED
        ) from exc
    start = 1
    if kind == AddressType.DOMAIN:
        if len(data) < 2:
            raise ProtocolError("missing domain length")
        size, start = data[1], 2
    else:
        size = 4 if kind == AddressType.IPV4 else 16
    end = start + size
    if len(data) < end + 2:
        raise ProtocolError("truncated address")
    try:
        encoded_host = data[start:end]
        if kind == AddressType.DOMAIN:
            # Accept UTF-8 peers too, but emit an ASCII IDNA name on the wire.
            host = encoded_host.decode("utf-8")
        else:
            host = ipaddress.ip_address(encoded_host)
        port = struct.unpack("!H", data[end : end + 2])[0]
        return BoundAddress(host, port), end + 2
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError("invalid address", ReplyCode.ADDRESS_NOT_SUPPORTED) from exc


def encode_connect(target: Target) -> bytes:
    return bytes([VERSION, Command.CONNECT, 0]) + encode_address(target)


def encode_reply(reply: int, bound: BoundAddress | None = None) -> bytes:
    if bound is None:
        bound = BoundAddress(ipaddress.IPv4Address("0.0.0.0"), 0)
    return bytes([VERSION, reply, 0]) + encode_address(bound)
