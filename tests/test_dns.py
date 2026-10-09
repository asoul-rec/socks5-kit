"""DNS callback semantics and local UDP/TCP interoperability checks."""

import asyncio
import errno
import ipaddress
import socket
import struct

import pytest

from socks5_kit.dns import DnsOptions, DnsRecordType, DnsServer
from socks5_kit.models import BoundAddress, Target


def question(
    domain="MiXeD.example",
    *,
    identifier=1234,
    qtype=1,
    qclass=1,
    flags=0x100,
    edns_size=None,
):
    labels = domain.rstrip(".").split(".") if domain != "." else []
    name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
    packet = (
        struct.pack("!6H", identifier, flags, 1, 0, 0, edns_size is not None)
        + name
        + b"\0"
        + (struct.pack("!2H", qtype, qclass))
    )
    if edns_size is not None:
        packet += b"\0" + struct.pack("!HHIH", 41, edns_size, 0, 0)
    return packet


def read_name(packet, offset):
    """Independently expand standard DNS names in successful server replies."""
    labels = []
    end = None
    seen = set()
    while True:
        assert offset not in seen
        seen.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((size & 0x3F) << 8) | packet[offset + 1]
        elif size == 0:
            return b".".join(labels), end if end is not None else offset + 1
        else:
            assert size < 64
            labels.append(packet[offset + 1 : offset + size + 1])
            offset += size + 1


def response(packet):
    identifier, flags, questions, answers, authority, additional = struct.unpack_from(
        "!6H", packet
    )
    offset = 12
    received_questions = []
    for _ in range(questions):
        name, offset = read_name(packet, offset)
        qtype, qclass = struct.unpack_from("!2H", packet, offset)
        offset += 4
        received_questions.append((name, qtype, qclass))
    records = []
    for index in range(answers + authority + additional):
        name, offset = read_name(packet, offset)
        kind, rclass, ttl, size = struct.unpack_from("!2HIH", packet, offset)
        offset += 10
        data = packet[offset : offset + size]
        assert len(data) == size
        if kind == 5:
            data, name_end = read_name(packet, offset)
            assert name_end == offset + size
        offset += size
        records.append((name, kind, rclass, ttl, data, index < answers))
    assert offset == len(packet)
    return identifier, flags, received_questions, records


def assert_reply(
    packet,
    *,
    identifier=1234,
    rcode=0,
    address=None,
    cname=None,
    ttl=0,
    truncated=False,
):
    received_id, flags, questions, records = response(packet)
    assert received_id == identifier
    assert flags & 0x8000  # QR
    assert flags & 0xF == rcode
    assert not flags & (0x80 | 0x20)  # RA and AD stay clear.
    assert bool(flags & 0x200) is truncated
    answers = [record for record in records if record[-1]]
    if cname is not None:
        assert address is None
        assert answers == [
            (questions[0][0], 5, 1, ttl, cname.rstrip(".").encode("ascii"), True)
        ]
    elif address is None:
        assert not answers
    else:
        parsed = ipaddress.ip_address(address)
        assert answers == [
            (
                questions[0][0],
                1 if parsed.version == 4 else 28,
                1,
                ttl,
                parsed.packed,
                True,
            )
        ]
    return flags, questions


def run(scenario):
    async def bounded():
        async with asyncio.timeout(10):
            await scenario()

    asyncio.run(bounded())


async def wait_for(predicate):
    async with asyncio.timeout(2):
        while not predicate():  # noqa: ASYNC110 - observe public resource counters
            await asyncio.sleep(0)


def test_callback_receives_normalized_domain_and_a_ttl():
    async def scenario():
        calls = []

        def lookup(domain, qtype):
            calls.append((domain, qtype))
            return ipaddress.IPv4Address("192.0.2.10")

        server = DnsServer(lookup, options=DnsOptions(ttl=17))
        async with server:
            assert server.address is None
            packet = await server._answer(question())
            flags, questions = assert_reply(packet, address="192.0.2.10", ttl=17)
            assert questions == [(b"MiXeD.example", 1, 1)]
            assert flags & 0x100  # Preserve recursion desired without performing it.
            assert calls == [("mixed.example", DnsRecordType.A)]
            assert server.active_queries == 0

    run(scenario)


def test_async_callback_and_repeated_queries_are_not_cached():
    async def scenario():
        calls = []

        async def lookup(domain, _qtype):
            calls.append(domain)
            await asyncio.sleep(0)
            return ipaddress.IPv4Address(f"192.0.2.{len(calls)}")

        async with DnsServer(lookup, options=DnsOptions(ttl=60)) as server:
            first = await server._answer(question())
            second = await server._answer(question())
            assert_reply(first, address="192.0.2.1", ttl=60)
            assert_reply(second, address="192.0.2.2", ttl=60)
            assert calls == ["mixed.example", "mixed.example"]

    run(scenario)


@pytest.mark.parametrize("qtype", [1, 5, 28])
@pytest.mark.parametrize("resolved", [None, ipaddress.IPv4Address("192.0.2.20")])
def test_supported_queries_distinguish_existing_and_missing_domains(qtype, resolved):
    async def scenario():
        calls = []

        def lookup(domain, _qtype):
            calls.append(domain)
            return resolved

        async with DnsServer(lookup) as server:
            packet = await server._answer(question(qtype=qtype))
            assert_reply(
                packet,
                rcode=3 if resolved is None else 0,
                address=resolved if qtype == 1 else None,
            )
            assert calls == ["mixed.example"]

    run(scenario)


@pytest.mark.parametrize("qtype", [2, 6, 12, 15, 16, 255, 65535])
def test_other_record_types_are_empty_without_calling_callback(qtype):
    async def scenario():
        def unexpected(_domain, _qtype):
            pytest.fail("unsupported record types must not invoke callback")

        async with DnsServer(unexpected) as server:
            packet = await server._answer(question("missing.example", qtype=qtype))
            _, questions = assert_reply(packet)
            assert questions == [(b"missing.example", qtype, 1)]

    run(scenario)


@pytest.mark.parametrize(
    ("qtype", "resolved"),
    [
        (DnsRecordType.A, ipaddress.IPv4Address("192.0.2.15")),
        (DnsRecordType.AAAA, ipaddress.IPv6Address("2001:db8::15")),
    ],
)
@pytest.mark.parametrize("asynchronous", [False, True])
def test_two_argument_resolver_receives_record_type(qtype, resolved, asynchronous):
    async def scenario():
        calls = []

        def resolve(domain, requested_type):
            assert isinstance(requested_type, DnsRecordType)
            calls.append((domain, requested_type))
            return resolved

        async def resolve_async(domain, requested_type):
            await asyncio.sleep(0)
            return resolve(domain, requested_type)

        callback = resolve_async if asynchronous else resolve
        async with DnsServer(callback, options=DnsOptions(ttl=37)) as server:
            assert_reply(
                await server._answer(question(qtype=qtype)), address=resolved, ttl=37
            )
            assert calls == [("mixed.example", qtype)]
            assert server.active_queries == 0

    run(scenario)


def test_ipv6_object_answers_only_aaaa_queries():
    async def scenario():
        calls = []

        def lookup(domain, _qtype):
            calls.append(domain)
            return ipaddress.IPv6Address("2001:db8::42")

        async with DnsServer(lookup) as server:
            assert_reply(
                await server._answer(question(qtype=28)), address="2001:db8::42"
            )
            assert_reply(await server._answer(question(qtype=1)))
            assert_reply(await server._answer(question(qtype=5)))
            assert calls == ["mixed.example"] * 3

    run(scenario)


def test_optional_second_parameter_always_receives_requested_type():
    async def scenario():
        marker = object()
        calls = []

        def lookup(domain, context=marker):
            calls.append((domain, context))
            return ipaddress.IPv6Address("2001:db8::7")

        async with DnsServer(lookup) as server:
            assert_reply(
                await server._answer(question(qtype=28)), address="2001:db8::7"
            )
            assert calls == [("mixed.example", DnsRecordType.AAAA)]

    run(scenario)


def test_one_argument_resolver_returns_servfail_without_calling_its_body():
    async def scenario():
        calls = []

        def legacy(domain):
            calls.append(domain)
            return ipaddress.IPv6Address("2001:db8::9")

        async with DnsServer(legacy) as server:
            assert_reply(await server._answer(question(qtype=28)), rcode=2)
            assert not calls

    run(scenario)


@pytest.mark.parametrize("qtype", [1, 5, 28])
def test_cname_answer_is_returned_once_without_following_target(qtype):
    async def scenario():
        calls = []

        async def lookup(domain, requested_type):
            calls.append((domain, requested_type))
            return "Canonical.Example."

        async with DnsServer(lookup, options=DnsOptions(ttl=19)) as server:
            packet = await server._answer(question(qtype=qtype))
            _, questions = assert_reply(packet, cname="canonical.example", ttl=19)
            assert questions == [(b"MiXeD.example", qtype, 1)]
            assert calls == [("mixed.example", DnsRecordType(qtype))]
            assert server.active_queries == 0

    run(scenario)


@pytest.mark.parametrize(
    ("target", "normalized"),
    [
        ("BÜCHER.Example.", "xn--bcher-kva.example"),
        ("already.example", "already.example"),
        (".", "."),
    ],
)
def test_cname_target_normalization_and_wire_encoding(target, normalized):
    async def scenario():
        async with DnsServer(lambda _domain, _qtype: target) as server:
            assert_reply(await server._answer(question()), cname=normalized)

    run(scenario)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "a..example",
        "a" * 64 + ".example",
        ".".join(["a" * 63] * 4),
        "bad domain.example",
        "bad\\domain.example",
        "control\x00.example",
        "control\x1f.example",
        "control\x7f.example",
    ],
)
def test_invalid_domain_strings_return_servfail(target):
    async def scenario():
        async with DnsServer(lambda _domain, _qtype: target) as server:
            assert_reply(await server._answer(question()), rcode=2)
            assert server.active_queries == 0

    run(scenario)


@pytest.mark.parametrize("qtype", [1, 5, 28])
@pytest.mark.parametrize(
    "domain", ["canonical.example", "127.0.0.1", "2001:db8::15", "fe80::1%eth0"]
)
def test_strings_are_always_cname_targets_including_numeric_addresses(qtype, domain):
    async def scenario():
        async with DnsServer(lambda _domain, _qtype: domain) as server:
            assert_reply(await server._answer(question(qtype=qtype)), cname=domain)

    run(scenario)


def test_resolver_type_error_is_not_retried_as_another_signature():
    async def scenario():
        calls = []

        def lookup(domain, qtype):
            calls.append((domain, qtype))
            raise TypeError("a failure inside the callback")

        async with DnsServer(lookup) as server:
            assert_reply(await server._answer(question(qtype=28)), rcode=2)
            assert calls == [("mixed.example", DnsRecordType.AAAA)]

    run(scenario)


@pytest.mark.parametrize(
    "resolved",
    [
        True,
        0xC0000201,
        "not an address",
        ipaddress.IPv6Address("fe80::1%eth0"),
        b"\xc0\x00\x02\x01",
        Target(ipaddress.IPv4Address("192.0.2.1"), 53),
        BoundAddress(ipaddress.IPv6Address("2001:db8::1"), 53),
    ],
)
def test_invalid_callback_results_return_servfail(resolved):
    async def scenario():
        async with DnsServer(lambda _domain, _qtype: resolved) as server:
            assert_reply(await server._answer(question()), rcode=2)
            assert server.active_queries == 0

    run(scenario)


def test_callback_failure_returns_servfail():
    async def scenario():
        def lookup(_domain, _qtype):
            raise RuntimeError("lookup failed")

        async with DnsServer(lookup) as server:
            assert_reply(await server._answer(question()), rcode=2)
            assert server.active_queries == 0

    run(scenario)


def test_callback_timeout_cancels_lookup_and_returns_servfail():
    async def scenario():
        cancelled = asyncio.Event()

        async def lookup(_domain, _qtype):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        async with DnsServer(
            lookup, options=DnsOptions(callback_timeout=0.01)
        ) as server:
            assert_reply(await server._answer(question()), rcode=2)
            assert cancelled.is_set()
            assert server.active_queries == 0

    run(scenario)


@pytest.mark.parametrize(
    ("packet", "rcode"),
    [(question(flags=0x900), 4), (question(qclass=3), 5)],
)
def test_unsupported_requests_do_not_call_callback(packet, rcode):
    async def scenario():
        def unexpected(_domain, _qtype):
            pytest.fail("unsupported requests must not invoke callback")

        async with DnsServer(unexpected) as server:
            assert_reply(await server._answer(packet), rcode=rcode)

    run(scenario)


@pytest.mark.parametrize("packet", [b"short", question(flags=0x8100)])
def test_responses_and_short_datagrams_are_ignored(packet):
    async def scenario():
        def unexpected(_domain, _qtype):
            pytest.fail("non-query packets must not invoke callback")

        async with DnsServer(unexpected) as server:
            assert await server._answer(packet) is None

    run(scenario)


async def udp_exchange(sock, endpoint, packet):
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, packet, endpoint)
    data, sender = await loop.sock_recvfrom(sock, 65535)
    assert sender[:2] == endpoint[:2]
    return data


async def tcp_reply(reader):
    size = struct.unpack("!H", await reader.readexactly(2))[0]
    return await reader.readexactly(size)


def tcp_frame(packet):
    return struct.pack("!H", len(packet)) + packet


@pytest.mark.tcp_loopback
def test_udp_and_tcp_listen_on_same_ephemeral_port():
    async def scenario():
        calls = []

        async def lookup(domain, _qtype):
            calls.append(domain)
            await asyncio.sleep(0)
            return (
                None
                if domain == "missing.example"
                else ipaddress.IPv4Address("192.0.2.5")
            )

        async with DnsServer(lookup) as server:
            await server.start(port=0)
            assert server.address[0] == "127.0.0.1"
            assert server.address[1] > 0
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                packet = await udp_exchange(sock, server.address, question())
                assert_reply(packet, address="192.0.2.5")
                packet = await udp_exchange(
                    sock, server.address, question("Missing.example", identifier=43)
                )
                assert_reply(packet, identifier=43, rcode=3)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(tcp_frame(question(identifier=44)))
                await writer.drain()
                assert_reply(
                    await tcp_reply(reader), identifier=44, address="192.0.2.5"
                )
            finally:
                writer.close()
                await writer.wait_closed()
            await wait_for(lambda: server.active_connections == 0)
            assert calls == ["mixed.example", "missing.example", "mixed.example"]
            assert server.active_queries == 0
        assert server.active_connections == 0
        await server.aclose()

    run(scenario)


@pytest.mark.tcp_loopback
def test_tcp_pipeline_and_fragmented_frame_remain_ordered():
    async def scenario():
        calls = []

        async def lookup(domain, _qtype):
            calls.append(domain)
            await asyncio.sleep(0)
            return ipaddress.IPv4Address("198.51.100.9")

        async with DnsServer(lookup) as server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                # Several queries share one connection and one write.
                packets = [
                    question(f"query{n}.example", identifier=n) for n in range(4)
                ]
                writer.write(b"".join(tcp_frame(packet) for packet in packets))
                await writer.drain()
                for identifier in range(4):
                    assert_reply(
                        await tcp_reply(reader),
                        identifier=identifier,
                        address="198.51.100.9",
                    )
                # A subsequent frame arrives in separate header and body pieces.
                frame = tcp_frame(question("last.example", identifier=99))
                for part in (frame[:1], frame[1:5], frame[5:]):
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0)
                assert_reply(
                    await tcp_reply(reader), identifier=99, address="198.51.100.9"
                )
                assert calls == [
                    *(f"query{n}.example" for n in range(4)),
                    "last.example",
                ]
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
def test_udp_ignores_non_queries_then_accepts_valid_request():
    async def scenario():
        calls = []

        def lookup(domain, _qtype):
            calls.append(domain)
            return ipaddress.IPv4Address("203.0.113.7")

        async with DnsServer(lookup) as server:
            await server.start(port=0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                loop = asyncio.get_running_loop()
                await loop.sock_sendto(sock, b"bad", server.address)
                await loop.sock_sendto(
                    sock, question(identifier=88, flags=0x8100), server.address
                )
                packet = await udp_exchange(
                    sock, server.address, question(identifier=89)
                )
                assert_reply(packet, identifier=89, address="203.0.113.7")
                assert calls == ["mixed.example"]

    run(scenario)


@pytest.mark.tcp_loopback
def test_close_cancels_udp_callback_and_idle_tcp_connections():
    async def scenario():
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def lookup(_domain, _qtype):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        server = DnsServer(lookup)
        async with server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                await wait_for(lambda: server.active_connections == 1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    await asyncio.get_running_loop().sock_sendto(
                        sock, question(), server.address
                    )
                    await entered.wait()
                    assert server.active_queries == 1
                    await server.aclose()
                    assert cancelled.is_set()
                    assert server.active_queries == server.active_connections == 0
                    assert await reader.read() == b""
                with pytest.raises(RuntimeError):
                    await server.start(port=0)
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
def test_udp_pending_limit_drops_excess_then_recovers():
    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def lookup(domain, _qtype):
            calls.append(domain)
            entered.set()
            await release.wait()
            return ipaddress.IPv4Address("192.0.2.42")

        async with DnsServer(
            lookup, options=DnsOptions(max_pending_queries=1)
        ) as server:
            await server.start(port=0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                loop = asyncio.get_running_loop()
                await loop.sock_sendto(
                    sock, question("first.example", identifier=1), server.address
                )
                await entered.wait()
                await loop.sock_sendto(
                    sock, question("excess.example", identifier=2), server.address
                )
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.03):
                        await loop.sock_recvfrom(sock, 65535)
                assert calls == ["first.example"]
                release.set()
                packet, _ = await loop.sock_recvfrom(sock, 65535)
                assert_reply(packet, identifier=1, address="192.0.2.42")
                packet = await udp_exchange(
                    sock, server.address, question("third.example", identifier=3)
                )
                assert_reply(packet, identifier=3, address="192.0.2.42")
                assert calls == ["first.example", "third.example"]

    run(scenario)


@pytest.mark.tcp_loopback
def test_tcp_pending_limit_returns_servfail_while_udp_callback_is_running():
    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def lookup(domain, _qtype):
            calls.append(domain)
            entered.set()
            await release.wait()
            return ipaddress.IPv4Address("192.0.2.3")

        async with DnsServer(
            lookup, options=DnsOptions(max_pending_queries=1)
        ) as server:
            await server.start(port=0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                await asyncio.get_running_loop().sock_sendto(
                    sock, question("slow.example"), server.address
                )
                await entered.wait()
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(tcp_frame(question("busy.example", identifier=2)))
                    await writer.drain()
                    assert_reply(await tcp_reply(reader), identifier=2, rcode=2)
                    assert calls == ["slow.example"]
                    release.set()
                    await asyncio.get_running_loop().sock_recvfrom(sock, 65535)
                    await wait_for(lambda: server.active_queries == 0)
                    writer.write(tcp_frame(question("free.example", identifier=3)))
                    await writer.drain()
                    assert_reply(
                        await tcp_reply(reader), identifier=3, address="192.0.2.3"
                    )
                    assert calls == ["slow.example", "free.example"]
                finally:
                    writer.close()
                    await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
def test_tcp_connection_limit_and_idle_timeout_release_resources():
    async def scenario():
        async with DnsServer(
            lambda _domain, _qtype: ipaddress.IPv4Address("192.0.2.1"),
            options=DnsOptions(max_tcp_connections=1, tcp_idle_timeout=0.1),
        ) as server:
            await server.start(port=0)
            first_reader, first_writer = await asyncio.open_connection(*server.address)
            try:
                await wait_for(lambda: server.active_connections == 1)
                second_reader, second_writer = await asyncio.open_connection(
                    *server.address
                )
                try:
                    assert await second_reader.read() == b""
                    assert server.active_connections == 1
                finally:
                    second_writer.close()
                    await second_writer.wait_closed()
                assert await first_reader.read() == b""
                await wait_for(lambda: server.active_connections == 0)
            finally:
                first_writer.close()
                await first_writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize(
    ("qtype", "resolved", "expected"),
    [
        (1, ipaddress.IPv4Address("192.0.2.6"), {"address": "192.0.2.6"}),
        (28, ipaddress.IPv6Address("2001:db8::6"), {"address": "2001:db8::6"}),
        (1, "target.example", {"cname": "target.example"}),
        (5, "target.example", {"cname": "target.example"}),
        (28, "target.example", {"cname": "target.example"}),
    ],
)
def test_ipv6_udp_and_tcp_return_a_aaaa_and_cname(qtype, resolved, expected):
    async def scenario():
        calls = []

        def lookup(domain, requested_type):
            calls.append((domain, requested_type))
            return resolved

        server = DnsServer(lookup)
        async with server:
            try:
                await server.start("::1", 0)
            except OSError as exc:
                if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                    pytest.skip(f"IPv6 loopback is unavailable: {exc}")
                raise
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                assert_reply(
                    await udp_exchange(sock, server.address, question(qtype=qtype)),
                    **expected,
                )
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(tcp_frame(question(identifier=6, qtype=qtype)))
                await writer.drain()
                assert_reply(await tcp_reply(reader), identifier=6, **expected)
                assert calls == [("mixed.example", DnsRecordType(qtype))] * 2
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize("edns_size", [None, 1232])
def test_long_cname_udp_limit_and_complete_tcp_response(edns_size):
    async def scenario():
        domain = ".".join(["q" * 63] * 3 + ["q" * 61])
        target = ".".join(["c" * 63] * 3 + ["c" * 61])
        calls = []

        def lookup(requested_domain, requested_type):
            calls.append((requested_domain, requested_type))
            return target

        async with DnsServer(lookup) as server:
            await server.start(port=0)
            packet = question(domain, qtype=28, edns_size=edns_size)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                reply = await udp_exchange(sock, server.address, packet)
                # This minimal server advertises a 512-byte UDP capacity even
                # when a client offers a larger EDNS size; retry over TCP.
                assert len(reply) <= 512
                assert_reply(reply, truncated=True)
                if edns_size is not None:
                    records = response(reply)[3]
                    opt = [record for record in records if record[1] == 41]
                    assert len(opt) == 1
                    assert opt[0][2] == 512
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(tcp_frame(packet))
                await writer.drain()
                reply = await tcp_reply(reader)
                assert len(reply) > 512
                assert_reply(reply, cname=target)
                assert calls == [(domain, DnsRecordType.AAAA)] * 2
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize("failure", [OSError, asyncio.CancelledError])
def test_failed_start_releases_both_listeners_and_allows_retry(monkeypatch, failure):
    async def scenario():
        server = DnsServer(lambda _domain, _qtype: ipaddress.IPv4Address("192.0.2.11"))
        original = asyncio.Server.start_serving
        attempts = 0
        old_closed = old_endpoint = None

        async def fail_first_start(listener):
            nonlocal attempts, old_closed, old_endpoint
            attempts += 1
            if attempts == 1:
                old_closed = server._udp_closed
                old_endpoint = server._udp_transport.get_extra_info("sockname")
                raise failure("forced start failure")
            await original(listener)

        monkeypatch.setattr(asyncio.Server, "start_serving", fail_first_start)
        async with server:
            with pytest.raises(failure):
                await server.start(port=0)
            assert server.address is None
            assert old_closed.done()
            # Binding the very same port also proves failed startup released UDP.
            await server.start(port=old_endpoint[1])
            assert server._udp_closed is not old_closed
            assert not server._udp_closed.done()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                assert_reply(
                    await udp_exchange(sock, server.address, question()),
                    address="192.0.2.11",
                )
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(tcp_frame(question()))
                await writer.drain()
                assert_reply(await tcp_reply(reader), address="192.0.2.11")
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_callback_can_close_its_own_server_without_deadlock(transport):
    async def scenario():
        finished = asyncio.Event()

        async def lookup(_domain, _qtype):
            await server.aclose()
            finished.set()
            return ipaddress.IPv4Address("192.0.2.1")

        async with DnsServer(lookup) as server:
            await server.start(port=0)
            if transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    await asyncio.get_running_loop().sock_sendto(
                        sock, question(), server.address
                    )
                    await finished.wait()
            else:
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(tcp_frame(question()))
                    await writer.drain()
                    await finished.wait()
                    assert await reader.read() == b""
                finally:
                    writer.close()
                    await writer.wait_closed()
            await wait_for(
                lambda: server.active_queries == server.active_connections == 0
            )
            assert server.address is None

    run(scenario)


@pytest.mark.tcp_loopback
def test_cancelled_close_waits_for_cleanup_before_propagating(monkeypatch):
    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        server = DnsServer(lambda _domain, _qtype: ipaddress.IPv4Address("192.0.2.1"))
        original = server._close

        async def delayed_close(initiator):
            entered.set()
            await release.wait()
            await original(initiator)

        monkeypatch.setattr(server, "_close", delayed_close)
        async with server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                await wait_for(lambda: server.active_connections == 1)
                close_task = asyncio.create_task(server.aclose())
                await entered.wait()
                close_task.cancel()
                # Cancellation is deferred until the separately owned cleanup ends.
                await asyncio.sleep(0)
                assert not close_task.done()
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await close_task
                assert server.address is None
                assert server.active_queries == server.active_connections == 0
                assert await reader.read() == b""
            finally:
                release.set()
                writer.close()
                await writer.wait_closed()

    run(scenario)


def test_close_aborts_backpressured_writer_before_waiting_for_it():
    async def scenario():
        class BackpressuredWriter:
            def __init__(self):
                self.transport = self
                self.aborted = asyncio.Event()

            def abort(self):
                self.aborted.set()

            async def wait_closed(self):
                # A graceful close would be stuck until a peer reads buffered data.
                await self.aborted.wait()

        async with DnsServer(lambda _domain, _qtype: None) as server:
            writer = BackpressuredWriter()
            handler = asyncio.create_task(asyncio.Event().wait())
            server._connections[handler] = writer
            handler.add_done_callback(server._connection_done)
            await server.aclose()
            assert writer.aborted.is_set()
            assert handler.cancelled()
            assert server.active_connections == 0

    run(scenario)
