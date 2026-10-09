"""Small DNS wire codec for a callback-backed A/AAAA/CNAME server."""

import struct
from dataclasses import dataclass
from enum import IntEnum

_HEADER = struct.Struct("!HHHHHH")
_QUESTION = struct.Struct("!HH")
_RECORD = struct.Struct("!HHIH")
_QR = 0x8000
_AA = 0x0400
_TC = 0x0200
_COPIED_FLAGS = 0x7800 | 0x0100 | 0x0010  # OPCODE, RD, CD.
_OPT = 41
_UDP_CAPACITY = 512


class DnsFormatError(ValueError):
    """The packet cannot be interpreted as a supported DNS query."""


class Rcode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    BADVERS = 16


@dataclass(frozen=True, slots=True)
class Query:
    identifier: int
    flags: int
    labels: tuple[bytes, ...]
    qtype: int
    qclass: int
    edns_size: int | None = None
    edns_version: int = 0

    @property
    def domain(self) -> str:
        """Return a case-normalized name without a trailing root dot.

        Decimal escapes distinguish embedded separators and arbitrary binary
        label octets from the dots separating labels. IDNA A-labels stay ASCII.
        """
        if not self.labels:
            return "."
        return ".".join(
            "".join(
                chr(octet)
                if 0x21 <= octet <= 0x7E and octet not in (0x2E, 0x5C)
                else f"\\{octet:03d}"
                for octet in label.lower()
            )
            for label in self.labels
        )

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF


def _read_name(packet: bytes, offset: int) -> tuple[tuple[bytes, ...], int]:
    labels = []
    seen = set()
    end = None
    expanded_size = 1  # The terminal root label.
    while True:
        if offset >= len(packet):
            raise DnsFormatError("truncated domain name")
        if offset in seen:
            raise DnsFormatError("compression pointer loop")
        seen.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise DnsFormatError("truncated compression pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length & 0xC0:
            raise DnsFormatError("unsupported label encoding")
        offset += 1
        if not length:
            return tuple(labels), offset if end is None else end
        if offset + length > len(packet):
            raise DnsFormatError("truncated label")
        expanded_size += length + 1
        if expanded_size > 255:
            raise DnsFormatError("domain name exceeds 255 octets")
        labels.append(packet[offset : offset + length])
        offset += length


def _check_options(packet: bytes, start: int, end: int) -> None:
    while start < end:
        if end - start < 4:
            raise DnsFormatError("truncated EDNS option header")
        size = int.from_bytes(packet[start + 2 : start + 4])
        start += 4 + size
        if start > end:
            raise DnsFormatError("truncated EDNS option data")


def parse_query(packet: bytes) -> Query | None:
    """Parse one query, safely expanding names and skipping other records.

    Short packets and responses are ignored. Complete but malformed queries
    raise DnsFormatError so their header can be used for a FORMERR response.
    """
    if len(packet) < _HEADER.size:
        return None
    identifier, flags, questions, answers, authorities, additionals = (
        _HEADER.unpack_from(packet)
    )
    if flags & _QR:
        return None
    if questions != 1:
        raise DnsFormatError("exactly one question is required")
    labels, offset = _read_name(packet, _HEADER.size)
    if len(packet) - offset < _QUESTION.size:
        raise DnsFormatError("truncated question")
    qtype, qclass = _QUESTION.unpack_from(packet, offset)
    offset += _QUESTION.size
    edns_size = None
    edns_version = 0
    for section, count in enumerate((answers, authorities, additionals)):
        for _ in range(count):
            owner, offset = _read_name(packet, offset)
            if len(packet) - offset < _RECORD.size:
                raise DnsFormatError("truncated resource record")
            kind, rrclass, ttl, size = _RECORD.unpack_from(packet, offset)
            offset += _RECORD.size
            end = offset + size
            if end > len(packet):
                raise DnsFormatError("truncated resource record data")
            if kind == _OPT:
                if section != 2 or owner or edns_size is not None:
                    raise DnsFormatError("OPT must be a single root additional record")
                _check_options(packet, offset, end)
                edns_size = max(512, rrclass)
                edns_version = (ttl >> 16) & 0xFF
            offset = end
    # Ignore harmless trailing bytes rather than rejecting usable local queries.
    return Query(identifier, flags, labels, qtype, qclass, edns_size, edns_version)


def _encode_name(labels: tuple[bytes, ...]) -> bytes:
    if any(
        not isinstance(label, bytes) or not 1 <= len(label) <= 63 for label in labels
    ):
        raise ValueError("labels must contain 1 to 63 bytes")
    if 1 + sum(len(label) + 1 for label in labels) > 255:
        raise ValueError("domain name exceeds 255 octets")
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _check_upstream_parameters(qtype: int, identifier: int) -> None:
    if isinstance(qtype, bool) or not isinstance(qtype, int) or qtype not in (1, 28):
        raise ValueError("upstream queries require A or AAAA")
    if (
        isinstance(identifier, bool)
        or not isinstance(identifier, int)
        or not 0 <= identifier <= 65535
    ):
        raise ValueError("identifier must be an integer from 0 to 65535")


def encode_upstream_query(
    labels: tuple[bytes, ...], qtype: int, identifier: int
) -> bytes:
    """Request one IN/A or IN/AAAA answer with recursion desired."""
    _check_upstream_parameters(qtype, identifier)
    if not isinstance(labels, tuple):
        raise ValueError("labels must be a tuple of bytes")
    name = _encode_name(labels)
    return (
        _HEADER.pack(identifier, 0x0100, 1, 0, 0, 0) + name + _QUESTION.pack(qtype, 1)
    )


def decode_upstream_address(
    packet: bytes,
    *,
    identifier: int,
    labels: tuple[bytes, ...],
    qtype: int,
) -> bytes | None:
    """Extract the first matching address from a complete upstream answer.

    Unusable or unrelated responses return None. Malformed packets raise
    DnsFormatError. This deliberately does not follow CNAME chains: an address
    accompanying a CNAME in the answer section is sufficient, while addresses
    in authority/additional sections do not count.
    """
    _check_upstream_parameters(qtype, identifier)
    if not isinstance(labels, tuple):
        raise ValueError("labels must be a tuple of bytes")
    _encode_name(labels)
    if len(packet) < _HEADER.size:
        raise DnsFormatError("truncated upstream header")
    received_id, flags, questions, answers, authorities, additionals = (
        _HEADER.unpack_from(packet)
    )
    if (
        received_id != identifier
        or not flags & _QR
        or flags & (0x7800 | _TC | 0x000F)
        or questions != 1
    ):
        return None
    received_labels, offset = _read_name(packet, _HEADER.size)
    if len(packet) - offset < _QUESTION.size:
        raise DnsFormatError("truncated upstream question")
    received_type, received_class = _QUESTION.unpack_from(packet, offset)
    offset += _QUESTION.size
    if (
        tuple(label.lower() for label in received_labels)
        != tuple(label.lower() for label in labels)
        or received_type != qtype
        or received_class != 1
    ):
        return None
    address = None
    extended_rcode = 0
    has_opt = False
    for section, count in enumerate((answers, authorities, additionals)):
        for _ in range(count):
            owner, offset = _read_name(packet, offset)
            if len(packet) - offset < _RECORD.size:
                raise DnsFormatError("truncated upstream resource record")
            kind, rrclass, ttl, size = _RECORD.unpack_from(packet, offset)
            offset += _RECORD.size
            end = offset + size
            if end > len(packet):
                raise DnsFormatError("truncated upstream resource record data")
            if kind in (1, 28) and rrclass == 1:
                expected_size = 4 if kind == 1 else 16
                if size != expected_size:
                    raise DnsFormatError("invalid upstream address length")
                if section == 0 and kind == qtype and address is None:
                    address = packet[offset:end]
            elif kind == 5:
                _, name_end = _read_name(packet, offset)
                if name_end != end:
                    raise DnsFormatError("invalid upstream CNAME length")
            elif kind == _OPT:
                if section != 2 or owner or has_opt:
                    raise DnsFormatError("OPT must be a single root additional record")
                _check_options(packet, offset, end)
                extended_rcode = (ttl >> 24) & 0xFF
                has_opt = True
            offset = end
    return None if extended_rcode else address


def _response_flags(flags: int, rcode: int) -> int:
    authoritative = _AA if rcode in (Rcode.NOERROR, Rcode.NXDOMAIN) else 0
    return _QR | authoritative | (flags & _COPIED_FLAGS) | (rcode & 0xF)


def encode_response(
    query: Query,
    *,
    rcode: int = 0,
    address: bytes | None = None,
    cname: tuple[bytes, ...] | None = None,
    ttl: int = 0,
    udp: bool = False,
) -> bytes:
    """Build an uncompressed question and at most one A/AAAA/CNAME answer.

    EDNS responses advertise 512 octets. UDP replies exceeding that capacity
    omit the entire answer and set TC so a client can retry over TCP.
    Unsupported EDNS versions receive BADVERS with no answer.
    """
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= 0x7FFFFFFF:
        raise ValueError("TTL must be an integer from 0 to 2147483647")
    if isinstance(rcode, bool) or not isinstance(rcode, int) or not 0 <= rcode <= 0xFFF:
        raise ValueError("RCODE must be an integer from 0 to 4095")
    if query.edns_size is not None and query.edns_version:
        rcode = Rcode.BADVERS
        address = None
        cname = None
    if rcode > 15 and query.edns_size is None:
        raise ValueError("extended RCODE requires EDNS")
    if address is not None and cname is not None:
        raise ValueError("address and CNAME answers are mutually exclusive")
    answer = b""
    if address is not None:
        if not isinstance(address, bytes) or len(address) not in (4, 16):
            raise ValueError(
                "address must be four packed IPv4 bytes or sixteen packed IPv6 bytes"
            )
        kind = 1 if len(address) == 4 else 28
        if rcode or query.qtype != kind or query.qclass != 1:
            raise ValueError(
                "an address requires a successful IN/A or IN/AAAA query "
                "matching its address family"
            )
        answer = b"\xc0\x0c" + _RECORD.pack(kind, 1, ttl, len(address)) + address
    if cname is not None:
        if rcode or query.qtype not in (1, 5, 28) or query.qclass != 1:
            raise ValueError(
                "a CNAME requires a successful IN/A, IN/AAAA or IN/CNAME query"
            )
        target = _encode_name(cname)
        answer = b"\xc0\x0c" + _RECORD.pack(5, 1, ttl, len(target)) + target
    question = _encode_name(query.labels) + _QUESTION.pack(query.qtype, query.qclass)
    additional = b""
    if query.edns_size is not None:
        additional = b"\x00" + _RECORD.pack(_OPT, _UDP_CAPACITY, (rcode >> 4) << 24, 0)
    flags = _response_flags(query.flags, rcode)
    if (
        udp
        and _HEADER.size + len(question) + len(answer) + len(additional) > _UDP_CAPACITY
    ):
        answer = b""
        flags |= _TC
    return (
        _HEADER.pack(
            query.identifier, flags, 1, int(bool(answer)), 0, int(bool(additional))
        )
        + question
        + answer
        + additional
    )


def encode_error(packet: bytes, rcode: int) -> bytes | None:
    """Respond using only a trustworthy header, without copying malformed data."""
    if len(packet) < _HEADER.size:
        return None
    identifier, flags, *_ = _HEADER.unpack_from(packet)
    if flags & _QR:
        return None
    if isinstance(rcode, bool) or not isinstance(rcode, int) or not 0 <= rcode <= 15:
        raise ValueError("header-only error requires an RCODE from 0 to 15")
    # A malformed packet cannot establish authority for a particular name.
    flags = _QR | (flags & _COPIED_FLAGS) | rcode
    return _HEADER.pack(identifier, flags, 0, 0, 0, 0)
