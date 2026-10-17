"""Normal access logs describe connections without exposing application bytes."""

import asyncio
import ipaddress
import logging
import socket
import struct

import pytest

import socks5_kit.dns as dns_module
from socks5_kit import BoundAddress, Socks5Client, Socks5RewriteServer, Target
from socks5_kit.dns import DnsOptions, DnsServer
from socks5_kit.errors import RejectTarget, UpstreamRejected
from socks5_kit.protocol import encode_connect, encode_reply
from tests.test_dns import assert_reply, question
from tests.test_tcp import Service, downstream_reply, request, run, upstream_request

pytestmark = pytest.mark.tcp_loopback


def messages(caplog, logger, level=logging.INFO):
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == logger and record.levelno == level
    ]


def test_authenticated_rewrite_logs_success_without_password_or_payload(caplog):
    caplog.set_level(logging.DEBUG, logger="socks5_kit")
    password = b"private-password-do-not-log"
    payload = b"private-application-payload-do-not-log"
    original = Target("original.example", 443)
    rewritten = Target("rewritten.example", 8443)
    bound = BoundAddress(ipaddress.IPv4Address("192.0.2.10"), 1234)

    async def scenario():
        async def upstream(reader, writer):
            assert await upstream_request(reader, writer) == BoundAddress(
                rewritten.host, rewritten.port
            )
            writer.write(encode_reply(0, bound))
            await writer.drain()
            assert await reader.readexactly(len(payload)) == payload
            writer.write(payload)
            await writer.drain()
            await reader.read()

        def rewrite(target, context):
            assert target == original
            assert context.username == b"test-user"
            assert context.password == password
            return rewritten

        async with Service(upstream) as service:
            async with Socks5RewriteServer(
                rewrite, "127.0.0.1", service.port
            ) as server:
                await server.start(port=0)
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(
                        b"\x05\x01\x02\x01\x09test-user"
                        + bytes([len(password)])
                        + password
                        + encode_connect(original)
                        + payload
                    )
                    await writer.drain()
                    assert await reader.readexactly(4) == b"\x05\x02\x01\x00"
                    assert await downstream_reply(reader) == (0, bound)
                    assert await reader.readexactly(len(payload)) == payload
                finally:
                    writer.close()
                    await writer.wait_closed()

    run(scenario)
    rewrite_logs = messages(caplog, "socks5_kit.server")
    established = next(
        message for message in rewrite_logs if "SOCKS rewrite established " in message
    )
    assert "original.example" in established and "rewritten.example" in established
    assert "peer=" in established and "bound=" in established
    assert "session_id=" in established and "elapsed_ms=" in established
    assert any("server started " in message for message in rewrite_logs)
    assert any("server stopped " in message for message in rewrite_logs)
    assert any(
        "SOCKS client established " in message
        for message in messages(caplog, "socks5_kit.client")
    )
    assert password.decode() not in caplog.text
    assert payload.decode() not in caplog.text


def test_client_initial_data_and_coalesced_banner_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG, logger="socks5_kit.client")
    initial = b"private-initial-bytes-do-not-log"
    banner = b"private-server-banner-do-not-log"

    async def scenario():
        async def proxy(reader, writer):
            assert await upstream_request(reader, writer) == BoundAddress(
                "test.example", 80
            )
            # REP deliberately depends on initial_data arriving first.
            assert await reader.readexactly(len(initial)) == initial
            writer.write(encode_reply(0) + banner)
            await writer.drain()
            await reader.read()

        async with Service(proxy) as service:
            async with await Socks5Client("127.0.0.1", service.port).connect(
                Target("test.example", 80), initial_data=initial
            ) as tunnel:
                assert await tunnel.recv() == banner

    run(scenario)
    logs = messages(caplog, "socks5_kit.client")
    assert len(logs) == 1 and "SOCKS client established " in logs[0]
    assert "proxy=" in logs[0] and "client_id=" in logs[0]
    assert initial.decode() not in caplog.text
    assert banner.decode() not in caplog.text


def test_client_rejection_logs_stage_without_traceback(caplog):
    caplog.set_level(logging.DEBUG, logger="socks5_kit.client")

    async def scenario():
        async def proxy(reader, writer):
            await upstream_request(reader, writer)
            writer.write(b"\x05\x05\x00")
            await writer.drain()
            await reader.read()

        async with Service(proxy) as service:
            with pytest.raises(UpstreamRejected):
                await Socks5Client("127.0.0.1", service.port).connect(
                    Target("unreachable.example", 443)
                )

    run(scenario)
    logs = messages(caplog, "socks5_kit.client", logging.WARNING)
    assert len(logs) == 1 and "SOCKS client failed " in logs[0]
    assert "stage=connect_reply" in logs[0]
    assert "error_type=UpstreamRejected" in logs[0]
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
@pytest.mark.parametrize("qtype,address", [(1, "192.0.2.7"), (28, "2001:db8::7")])
def test_dns_network_response_access_log(caplog, transport, qtype, address):
    caplog.set_level(logging.DEBUG, logger="socks5_kit.dns")

    async def scenario():
        server = DnsServer(lambda _domain, _kind: ipaddress.ip_address(address))
        async with server:
            await server.start(port=0)
            packet = question("access.example", qtype=qtype)
            if transport == "udp":
                loop = asyncio.get_running_loop()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    connection.setblocking(False)
                    await loop.sock_sendto(connection, packet, server.address)
                    reply, _peer = await loop.sock_recvfrom(connection, 65535)
            else:
                reader, writer = await asyncio.open_connection(*server.address)
                try:
                    writer.write(struct.pack("!H", len(packet)) + packet)
                    await writer.drain()
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                    reply = await reader.readexactly(size)
                finally:
                    writer.close()
                    await writer.wait_closed()
            assert_reply(reply, address=address)

    run(scenario)
    logs = messages(caplog, "socks5_kit.dns")
    response = next(message for message in logs if "event=dns_response " in message)
    assert f"transport={transport!r}" in response
    assert "domain='access.example'" in response and f"qtype={qtype}" in response
    assert "rcode=0" in response and "answer_count=1" in response
    assert "query_id=" in response and "peer=('127.0.0.1'," in response
    assert "elapsed_ms=" in response
    assert any("event=dns_server_started " in message for message in logs)
    assert any("DNS server stopped " in message for message in logs)


def test_callback_failure_log_does_not_expose_exception_contents(caplog):
    caplog.set_level(logging.DEBUG, logger="socks5_kit.dns")
    secret = "private-callback-secret-do-not-log"

    def resolve(_domain, _kind):
        raise RuntimeError(secret)

    async def scenario():
        async with DnsServer(resolve) as server:
            assert_reply(await server._answer(question()), rcode=2)

    run(scenario)
    assert secret not in caplog.text
    assert "error_type=RuntimeError" in caplog.text
    assert "rcode=2" in caplog.text and "answer_count=0" in caplog.text
    assert any(
        record.levelno == logging.ERROR and "DNS callback failed" in record.getMessage()
        for record in caplog.records
    )


def test_invalid_rewrite_result_is_not_logged(caplog):
    caplog.set_level(logging.DEBUG, logger="socks5_kit")
    secret = "private-invalid-callback-result-do-not-log"

    async def scenario():
        async with Socks5RewriteServer(lambda *_: secret, "127.0.0.1", 1080) as server:
            await server.start(port=0)
            _reader, writer, reply, _bound = await request(
                server, Target("invalid-result.example", 443)
            )
            try:
                assert reply == 1
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)
    assert secret not in caplog.text
    failure = next(
        message
        for message in messages(caplog, "socks5_kit.server", logging.ERROR)
        if "event=socks_rewrite_failed " in message
    )
    assert "stage='rewrite'" in failure and "error_type='TypeError'" in failure
    assert "invalid-result.example" in failure and "rewritten=" not in failure
    record = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "socks_rewrite_failed"
    )
    assert record.target == Target("invalid-result.example", 443)
    assert not hasattr(record, "rewritten")


def test_dns_badvers_log_matches_extended_rcode_with_unsupported_opcode(caplog):
    caplog.set_level(logging.INFO, logger="socks5_kit.dns")

    async def scenario():
        # encode_response upgrades the unsupported opcode reply to BADVERS
        # whenever the OPT record declares an unsupported EDNS version.
        packet = question(flags=0x900, edns_size=1232)
        packet = packet[:-6] + struct.pack("!I", 1 << 16) + packet[-2:]
        async with DnsServer(lambda *_: None) as server:
            reply = await server._answer(packet)
            assert reply[3] & 15 == 0
            assert reply[-6] == 1  # Extended RCODE: 1 << 4 == BADVERS.

    run(scenario)
    response = next(
        message
        for message in messages(caplog, "socks5_kit.dns")
        if "event=dns_response " in message
    )
    assert "rcode=16" in response and "answer_count=0" in response


def test_rewrite_handshake_failure_omits_unknown_targets(caplog):
    caplog.set_level(logging.INFO, logger="socks5_kit.server")

    async def scenario():
        async with Socks5RewriteServer(lambda *_: None, "127.0.0.1", 1080) as server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                writer.write(b"\x05\x01\x00\x04\x01\x00")
                await writer.drain()
                assert await reader.readexactly(2) == b"\x05\x00"
                assert (await downstream_reply(reader))[0] != 0
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)
    record = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "socks_rewrite_failed"
    )
    assert record.stage == "handshake" and record.error_type == "ProtocolError"
    assert record.levelno == logging.WARNING
    assert not hasattr(record, "target") and not hasattr(record, "rewritten")
    assert "target=" not in record.getMessage()
    assert "rewritten=" not in record.getMessage()


def test_malformed_dns_response_omits_unknown_question_and_network_context(caplog):
    caplog.set_level(logging.INFO, logger="socks5_kit.dns")

    async def scenario():
        async with DnsServer(lambda *_: None) as server:
            reply = await server._answer(question()[:-1])
            assert reply[3] & 15 == 1  # FORMERR, without a decoded question.

    run(scenario)
    record = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "dns_response"
    )
    assert record.rcode == 1 and record.answer_count == 0
    assert record.levelno == logging.WARNING
    for field in ("domain", "qtype", "peer", "listener"):
        assert not hasattr(record, field)
        assert f"{field}=" not in record.getMessage()


@pytest.mark.parametrize("upstream", [None, ("192.0.2.53", 53)])
def test_dns_start_log_includes_upstream_only_when_configured(caplog, upstream):
    caplog.set_level(logging.INFO, logger="socks5_kit.dns")

    async def scenario():
        async with DnsServer(lambda *_: None, upstream_dns=upstream) as server:
            await server.start(port=0)

    run(scenario)
    record = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "dns_server_started"
    )
    if upstream is None:
        assert not hasattr(record, "upstream")
        assert "upstream=" not in record.getMessage()
    else:
        assert record.upstream == upstream
        assert f"upstream={upstream!r}" in record.getMessage()


@pytest.mark.parametrize(
    "error,level,reply",
    [
        (RejectTarget, logging.INFO, 2),
        (TimeoutError, logging.WARNING, 1),
        (RuntimeError, logging.ERROR, 1),
    ],
)
def test_rewrite_failure_severity_distinguishes_policy_io_and_callback_bugs(
    caplog, error, level, reply
):
    caplog.set_level(logging.INFO, logger="socks5_kit.server")
    secret = "private-rewrite-exception-do-not-log"

    def rewrite(*_):
        raise error(secret)

    async def scenario():
        async with Socks5RewriteServer(rewrite, "127.0.0.1", 1080) as server:
            await server.start(port=0)
            _reader, writer, actual_reply, _bound = await request(
                server, Target("policy.example", 443)
            )
            try:
                assert actual_reply == reply
            finally:
                writer.close()
                await writer.wait_closed()

    run(scenario)
    record = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "socks_rewrite_failed"
    )
    assert record.levelno == level and record.error_type == error.__name__
    assert record.target == Target("policy.example", 443)
    assert secret not in caplog.text


@pytest.mark.parametrize(
    "result,level,error_type",
    [
        (b"private-invalid-dns-result-do-not-log", logging.ERROR, "TypeError"),
        (
            TimeoutError("private-dns-timeout-do-not-log"),
            logging.WARNING,
            "TimeoutError",
        ),
    ],
)
def test_dns_callback_invalid_result_and_timeout_levels(
    caplog, result, level, error_type
):
    caplog.set_level(logging.INFO, logger="socks5_kit.dns")

    def resolve(*_):
        if isinstance(result, Exception):
            raise result
        return result

    async def scenario():
        async with DnsServer(resolve) as server:
            assert_reply(await server._answer(question()), rcode=2)

    run(scenario)
    failure = next(
        record
        for record in caplog.records
        if "DNS callback failed " in record.getMessage()
    )
    assert failure.levelno == level
    assert f"error_type={error_type}" in failure.getMessage()
    assert "do-not-log" not in caplog.text


def test_dns_upstream_timeout_warns_and_preserves_alias_fallback(caplog):
    caplog.set_level(logging.INFO, logger="socks5_kit.dns")

    async def scenario():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.bind(("127.0.0.1", 0))
            async with DnsServer(
                lambda *_: "alias.example",
                upstream_dns=upstream.getsockname(),
                options=DnsOptions(upstream_timeout=0.01),
            ) as server:
                reply = await server._answer(question())
                assert reply[3] & 15 == 0 and int.from_bytes(reply[6:8]) == 1

    run(scenario)
    failure = next(
        record
        for record in caplog.records
        if "DNS upstream failed " in record.getMessage()
    )
    assert failure.levelno == logging.WARNING
    assert "error_type=TimeoutError" in failure.getMessage()


def test_dns_warning_level_still_reports_malformed_queries_without_normal_info(
    caplog, monkeypatch
):
    caplog.set_level(logging.WARNING, logger="socks5_kit.dns")
    parse_count = 0
    parse_query = dns_module.parse_query

    def tracked_parse_query(packet):
        nonlocal parse_count
        parse_count += 1
        return parse_query(packet)

    monkeypatch.setattr(dns_module, "parse_query", tracked_parse_query)

    async def scenario():
        async with DnsServer(lambda *_: None) as server:
            assert_reply(await server._answer(question()), rcode=3)
            assert parse_count == 1  # No additional access-log parsing at WARNING.
            assert not caplog.records
            assert (await server._answer(question()[:-1]))[3] & 15 == 1

    run(scenario)
    response = next(
        record
        for record in caplog.records
        if getattr(record, "event", None) == "dns_response"
    )
    assert response.levelno == logging.WARNING and response.rcode == 1
