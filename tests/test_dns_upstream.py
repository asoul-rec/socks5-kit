"""Optional CNAME completion against a controlled UDP DNS upstream."""

import asyncio
import errno
import ipaddress
import socket
import struct
from contextlib import asynccontextmanager

import pytest

from socks5_kit.dns import DnsOptions, DnsRecordType, DnsServer

from .test_dns import (
    assert_reply,
    question,
    response,
    run,
    tcp_frame,
    tcp_reply,
    udp_exchange,
)


def wire_name(domain):
    return (
        b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in domain.rstrip(".").split(".")
        )
        + b"\0"
    )


def record(kind, data, *, record_class=1, owner=b"\xc0\x0c"):
    return owner + struct.pack("!HHIH", kind, record_class, 3600, len(data)) + data


def upstream_reply(
    query,
    *,
    answers=(),
    additional=(),
    flags=0x8180,
    identifier=None,
    echoed_question=None,
):
    query_id = struct.unpack_from("!H", query)[0]
    return (
        struct.pack(
            "!6H",
            query_id if identifier is None else identifier,
            flags,
            1,
            len(answers),
            0,
            len(additional),
        )
        + (query[12:] if echoed_question is None else echoed_question)
        + b"".join(answers)
        + b"".join(additional)
    )


@asynccontextmanager
async def upstream(handler, *, family=socket.AF_INET):
    """Serve independent wire replies without using production DNS codecs."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    except OSError as exc:
        sock.close()
        if family == socket.AF_INET6 and exc.errno in (
            errno.EAFNOSUPPORT,
            errno.EADDRNOTAVAIL,
            errno.EPROTONOSUPPORT,
        ):
            pytest.skip(f"IPv6 loopback unavailable: {exc}")
        raise

    async def serve():
        while True:
            data, peer = await loop.sock_recvfrom(sock, 65535)
            replies = handler(data)
            if replies is None:
                continue
            if isinstance(replies, bytes):
                replies = (replies,)
            for reply in replies:
                await loop.sock_sendto(sock, reply, peer)

    task = asyncio.create_task(serve())
    try:
        yield sock.getsockname()[:2]
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            sock.close()


@pytest.mark.parametrize(
    ("endpoint", "canonical"),
    [
        (None, None),
        (("127.0.0.1", 5353), ("127.0.0.1", 5353)),
        (("2001:0db8:0:0:0:0:0:1", 53), ("2001:db8::1", 53)),
    ],
)
def test_constructor_normalizes_upstream_without_io(monkeypatch, endpoint, canonical):
    def forbidden(*_args, **_kwargs):
        pytest.fail("DNS construction must not perform network I/O")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    server = DnsServer(lambda _domain, _qtype: None, upstream_dns=endpoint)
    assert server.upstream_dns == canonical
    assert server.address is None
    assert server.active_queries == server.active_connections == 0


@pytest.mark.parametrize(
    "endpoint",
    [
        "127.0.0.1",
        (),
        ("127.0.0.1",),
        ("127.0.0.1", 53, 0),
        ("resolver.example", 53),
        ("999.0.0.1", 53),
        ("127.0.0.1", 0),
        ("127.0.0.1", 65536),
        ("127.0.0.1", True),
        ("127.0.0.1", "53"),
    ],
)
def test_invalid_upstream_endpoint_is_rejected(endpoint):
    with pytest.raises((TypeError, ValueError)):
        DnsServer(lambda _domain, _qtype: None, upstream_dns=endpoint)


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True, "2"])
def test_upstream_timeout_must_be_finite_and_positive(value):
    with pytest.raises((TypeError, ValueError)):
        DnsOptions(upstream_timeout=value)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize(
    ("qtype", "address"),
    [(DnsRecordType.A, "192.0.2.8"), (DnsRecordType.AAAA, "2001:db8::8")],
)
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_alias_is_completed_for_udp_and_tcp_clients(qtype, address, transport):
    async def scenario():
        calls = []
        upstream_queries = []
        packed = ipaddress.ip_address(address).packed

        def handle(packet):
            upstream_queries.append(packet)
            _, flags, questions, records = response(packet)
            assert flags & 0x100  # RD is set even if the downstream omitted it.
            assert not flags & 0x8000
            assert questions == [(b"canonical.example", qtype, 1)]
            assert not records  # No EDNS or unrelated query sections.
            return upstream_reply(packet, answers=[record(qtype, packed)])

        def resolve(domain, requested_type):
            calls.append((domain, requested_type))
            return "Canonical.Example."

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                resolve, upstream_dns=endpoint, options=DnsOptions(ttl=23)
            ) as server,
        ):
            await server.start(port=0)
            request = question(identifier=4321, qtype=qtype, flags=0)
            if transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.setblocking(False)
                    reply = await udp_exchange(client, server.address, request)
            else:
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(tcp_frame(request))
                    await writer.drain()
                    reply = await tcp_reply(reader)
                finally:
                    writer.close()
                    await writer.wait_closed()
            flags, questions = assert_reply(
                reply, identifier=4321, address=address, ttl=23
            )
            assert not flags & 0x100
            assert questions == [(b"MiXeD.example", qtype, 1)]
            assert calls == [("mixed.example", qtype)]
            assert len(upstream_queries) == 1
            assert server.active_queries == 0

    run(scenario)


@pytest.mark.tcp_loopback
def test_cname_and_multiple_addresses_use_first_matching_answer():
    async def scenario():
        def handle(packet):
            return upstream_reply(
                packet,
                answers=[
                    record(5, wire_name("another.example")),
                    record(28, ipaddress.IPv6Address("2001:db8::1").packed),
                    record(1, ipaddress.IPv4Address("192.0.2.1").packed),
                    record(1, ipaddress.IPv4Address("192.0.2.2").packed),
                ],
            )

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                lambda _domain, _qtype: "canonical.example", upstream_dns=endpoint
            ) as server,
        ):
            assert_reply(await server._answer(question()), address="192.0.2.1")

    run(scenario)


@pytest.mark.tcp_loopback
@pytest.mark.parametrize(
    "failure",
    [
        "timeout",
        "nxdomain",
        "servfail",
        "truncated",
        "cname_only",
        "nodata",
        "wrong_family",
        "wrong_class",
        "invalid_length",
        "glue_only",
        "malformed",
        "wrong_id",
        "wrong_question",
        "query_instead_of_response",
    ],
)
def test_upstream_failure_keeps_callback_cname(failure):
    async def scenario():
        calls = []
        upstream_queries = []

        def handle(packet):
            upstream_queries.append(packet)
            answer = record(1, ipaddress.IPv4Address("192.0.2.50").packed)
            if failure == "timeout":
                return None
            if failure == "malformed":
                return packet[:13]
            if failure == "cname_only":
                return upstream_reply(
                    packet, answers=[record(5, wire_name("second.example"))]
                )
            if failure == "nodata":
                return upstream_reply(packet)
            if failure == "wrong_family":
                answer = record(28, ipaddress.IPv6Address("2001:db8::1").packed)
            if failure == "wrong_class":
                answer = record(
                    1, ipaddress.IPv4Address("192.0.2.50").packed, record_class=3
                )
            if failure == "invalid_length":
                answer = record(1, b"\xc0\x00\x02")
            if failure == "glue_only":
                return upstream_reply(packet, additional=[answer])
            flags = {
                "nxdomain": 0x8183,
                "servfail": 0x8182,
                "truncated": 0x8380,
                "query_instead_of_response": 0x100,
            }.get(failure, 0x8180)
            identifier = None
            if failure == "wrong_id":
                identifier = (struct.unpack_from("!H", packet)[0] + 1) & 0xFFFF
            echoed_question = None
            if failure == "wrong_question":
                echoed_question = question("unrelated.example")[12:]
            return upstream_reply(
                packet,
                answers=[answer],
                flags=flags,
                identifier=identifier,
                echoed_question=echoed_question,
            )

        def resolve(domain, qtype):
            calls.append((domain, qtype))
            return "canonical.example"

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                resolve,
                upstream_dns=endpoint,
                options=DnsOptions(upstream_timeout=0.03, ttl=11),
            ) as server,
        ):
            assert_reply(
                await server._answer(question()), cname="canonical.example", ttl=11
            )
            assert calls == [("mixed.example", DnsRecordType.A)]
            assert len(upstream_queries) == 1
            assert server.active_queries == 0

    run(scenario)


@pytest.mark.tcp_loopback
def test_wrong_identifier_is_ignored_until_a_matching_reply_arrives():
    async def scenario():
        def handle(packet):
            answer = record(1, ipaddress.IPv4Address("192.0.2.9").packed)
            identifier = (struct.unpack_from("!H", packet)[0] + 1) & 0xFFFF
            wrong = upstream_reply(
                packet,
                answers=[record(1, ipaddress.IPv4Address("192.0.2.99").packed)],
                identifier=identifier,
            )
            return wrong, upstream_reply(packet, answers=[answer])

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                lambda _domain, _qtype: "canonical.example", upstream_dns=endpoint
            ) as server,
        ):
            assert_reply(await server._answer(question()), address="192.0.2.9")

    run(scenario)


@pytest.mark.parametrize(
    ("qtype", "result", "has_upstream"),
    [
        (1, "canonical.example", False),
        (28, "canonical.example", False),
        (5, "canonical.example", True),
        (1, ipaddress.IPv4Address("192.0.2.7"), True),
        (28, ipaddress.IPv6Address("2001:db8::7"), True),
        (1, None, True),
        (15, "canonical.example", True),
    ],
)
def test_other_callback_results_do_not_contact_upstream(
    monkeypatch, qtype, result, has_upstream
):
    async def scenario():
        def forbidden(*_args, **_kwargs):
            pytest.fail("this branch must not create an upstream socket")

        server = DnsServer(
            lambda _domain, _qtype: result,
            upstream_dns=("127.0.0.1", 53) if has_upstream else None,
        )
        async with server:
            # Patch after asyncio.run created its wakeup socket.
            with monkeypatch.context() as patch:
                patch.setattr(socket, "socket", forbidden)
                reply = await server._answer(question(qtype=qtype))
            assert_reply(
                reply,
                rcode=3 if result is None else 0,
                cname=result if isinstance(result, str) and qtype != 15 else None,
                address=(
                    str(result)
                    if isinstance(
                        result, (ipaddress.IPv4Address, ipaddress.IPv6Address)
                    )
                    else None
                ),
            )

    run(scenario)


@pytest.mark.tcp_loopback
def test_upstream_answers_are_not_cached():
    async def scenario():
        requests = []

        def handle(packet):
            requests.append(packet)
            address = ipaddress.IPv4Address(f"192.0.2.{len(requests)}")
            return upstream_reply(packet, answers=[record(1, address.packed)])

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                lambda _domain, _qtype: "canonical.example",
                upstream_dns=endpoint,
                options=DnsOptions(ttl=600),
            ) as server,
        ):
            assert_reply(await server._answer(question()), address="192.0.2.1", ttl=600)
            assert_reply(await server._answer(question()), address="192.0.2.2", ttl=600)
            assert len(requests) == 2

    run(scenario)


@pytest.mark.tcp_loopback
def test_ipv6_upstream_endpoint_can_complete_an_aaaa_alias():
    async def scenario():
        packed = ipaddress.IPv6Address("2001:db8::53").packed

        def handle(packet):
            return upstream_reply(packet, answers=[record(28, packed)])

        async with (
            upstream(handle, family=socket.AF_INET6) as endpoint,
            DnsServer(
                lambda _domain, _qtype: "canonical.example", upstream_dns=endpoint
            ) as server,
        ):
            assert_reply(
                await server._answer(question(qtype=28)), address="2001:db8::53"
            )

    run(scenario)


@pytest.mark.tcp_loopback
def test_close_cancels_pending_upstream_lookup_and_closes_its_socket(monkeypatch):
    async def scenario():
        received = asyncio.Event()
        outbound = []

        def handle(_packet):
            received.set()
            return None

        async with (
            upstream(handle) as endpoint,
            DnsServer(
                lambda _domain, _qtype: "canonical.example",
                upstream_dns=endpoint,
                options=DnsOptions(upstream_timeout=5),
            ) as server,
        ):
            await server.start(port=0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.setblocking(False)
                original = socket.socket

                def tracked(family, kind, *args, **kwargs):
                    sock = original(family, kind, *args, **kwargs)
                    if kind == socket.SOCK_DGRAM:
                        outbound.append(sock)
                    return sock

                with monkeypatch.context() as patch:
                    patch.setattr(socket, "socket", tracked)
                    await asyncio.get_running_loop().sock_sendto(
                        client, question(), server.address
                    )
                    await received.wait()
                    assert server.active_queries == 1
                    await server.aclose()
                assert len(outbound) == 1
                assert outbound[0].fileno() == -1
                assert server.active_queries == server.active_connections == 0

    run(scenario)
