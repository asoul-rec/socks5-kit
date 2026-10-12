"""Reverse resources, SOCKS identity isolation and real bidirectional relay I/O."""

import asyncio
import hashlib
import os
import random
from contextlib import asynccontextmanager
from dataclasses import replace
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit import BoundAddress, Socks5Client, Target
from socks5_kit.protocol import Command, encode_address, encode_connect, encode_reply
from socks5_kit.reverse import (
    DEFAULT_REVERSE_DOMAIN,
    ReverseAgent,
    ReverseAgentOptions,
    ReverseServer,
    ReverseServerOptions,
)
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO
from tests.test_auth_tcp import auth_frame
from tests.test_tcp import (
    Service,
    bridge,
    downstream_reply,
    run,
    stream_address,
    upstream_request,
)

pytestmark = pytest.mark.tcp_loopback
REGISTRATION = Target(DEFAULT_REVERSE_DOMAIN, 443)
DESTINATION = Target("destination.example", 80)


def immediate_server(*args, options=None, **kwargs):
    """Exercise immediate empty-pool rejection in these dispatch-focused tests."""
    options = replace(options or ReverseServerOptions(), max_pending_connections=0)
    return ReverseServer(*args, options=options, **kwargs)


async def eventually(predicate):
    async with asyncio.timeout(3):
        while not predicate():  # noqa: ASYNC110 - public counters have no change event
            await asyncio.sleep(0.001)


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


async def closed(reader):
    try:
        assert await reader.read() == b""
    except ConnectionResetError:
        # Failure replies may leave optional BND fields unread before close.
        pass


async def connect_request(
    server, target, *, user=None, password=b"", payload=b"", command=Command.CONNECT
):
    reader, writer = await asyncio.open_connection(*server.address)
    try:
        greeting = b"\x05\x01\x00"
        if user is not None:
            # Offer both methods and require the stronger method to win.
            greeting = b"\x05\x02\x00\x02" + auth_frame(user, password)
        writer.write(
            greeting + bytes([5, command, 0]) + encode_address(target) + payload
        )
        expected = b"\x05\x00" if user is None else b"\x05\x02\x01\x00"
        assert await reader.readexactly(len(expected)) == expected
        reply, bound = await downstream_reply(reader)
        return reader, writer, reply, bound
    except BaseException:
        await close_writer(writer)
        raise


@asynccontextmanager
async def resource(server, *, user=None, password=b"", target=REGISTRATION):
    before = server.idle_count(user)
    reader, writer, reply, bound = await connect_request(
        server, target, user=user, password=password, payload=REGISTRATION_HELLO
    )
    try:
        assert reply == 0
        assert bound == BoundAddress(IPv4Address("0.0.0.0"), 0)
        assert await reader.readexactly(len(REGISTRATION_ACK)) == REGISTRATION_ACK
        await eventually(lambda: server.idle_count(user) == before + 1)
        yield reader, writer
    finally:
        await close_writer(writer)


async def reverse_request(reader):
    # There is deliberately no second methods negotiation after registration.
    assert await reader.readexactly(3) == b"\x05\x01\x00"
    return await stream_address(reader)


async def failed_request(server, target=DESTINATION, **kwargs):
    reader, writer, reply, _bound = await connect_request(server, target, **kwargs)
    try:
        assert reply != 0
        assert await reader.read() == b""
        return reply
    finally:
        await close_writer(writer)


def test_fragmented_hello_is_not_published_before_complete_registration():
    async def scenario():
        async with immediate_server() as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(server, REGISTRATION)
            try:
                assert reply == 0
                assert server.resource_count == 1
                assert server.idle_connections == 0
                assert await failed_request(server) == 1
                writer.write(REGISTRATION_HELLO[:3])
                await writer.drain()
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.02):
                        await reader.read(1)
                assert server.idle_connections == 0
                writer.write(REGISTRATION_HELLO[3:])
                await writer.drain()
                assert (
                    await reader.readexactly(len(REGISTRATION_ACK)) == REGISTRATION_ACK
                )
                await eventually(lambda: server.idle_connections == 1)
            finally:
                await close_writer(writer)
            await eventually(lambda: server.resource_count == 0)

    run(scenario)


@pytest.mark.parametrize(
    ("hello", "eof"),
    [
        (b"NOPE\x01\x01", False),
        (b"S5KR\x02\x01", False),
        (REGISTRATION_ACK, False),
        (b"", True),
        (REGISTRATION_HELLO[:3], True),
        (b"", False),
        (REGISTRATION_HELLO[:3], False),
    ],
    ids=[
        "magic",
        "version",
        "opcode",
        "eof",
        "partial-eof",
        "timeout",
        "partial-timeout",
    ],
)
def test_failed_hello_closes_after_socks_success_without_ack_or_second_reply(
    hello, eof
):
    async def scenario():
        options = ReverseServerOptions(
            registration_timeout=0.03, max_resources=1, max_resources_per_user=1
        )
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(
                server, REGISTRATION, user=b"pending"
            )
            try:
                assert reply == 0
                assert server.resource_count == 1
                assert server.idle_count(b"pending") == 0
                writer.write(hello)
                await writer.drain()
                if eof:
                    writer.write_eof()
                assert await reader.read() == b""
                await eventually(lambda: server.resource_count == 0)
                assert server.idle_count(b"pending") == 0
            finally:
                await close_writer(writer)
            # Both total and username reservations must have been returned.
            async with resource(server, user=b"pending"):
                assert server.resource_count == server.idle_count(b"pending") == 1

    run(scenario)


def test_pending_hello_reserves_global_and_user_quotas_without_serving_business():
    async def scenario():
        options = ReverseServerOptions(max_resources=2, max_resources_per_user=1)
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(
                server, REGISTRATION, user=b"one"
            )
            try:
                assert reply == 0
                assert server.resource_count == 1
                assert server.idle_count(b"one") == 0
                assert await failed_request(server, user=b"one") == 1
                assert await failed_request(server, REGISTRATION, user=b"one") == 1
                async with resource(server, user=b"two"):
                    assert server.resource_count == 2
                    assert (
                        await failed_request(server, REGISTRATION, user=b"three") == 1
                    )
                await eventually(lambda: server.resource_count == 1)
                writer.write_eof()
                assert await reader.read() == b""
                await eventually(lambda: server.resource_count == 0)
            finally:
                await close_writer(writer)
            async with resource(server, user=b"one"):
                assert server.idle_count(b"one") == 1

    run(scenario)


def test_hello_with_trailing_bytes_acknowledges_exact_frame_then_retires_resource():
    async def scenario():
        async with immediate_server() as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(
                server, REGISTRATION, payload=REGISTRATION_HELLO + b"unsolicited bytes"
            )
            try:
                assert reply == 0
                assert (
                    await reader.readexactly(len(REGISTRATION_ACK)) == REGISTRATION_ACK
                )
                await closed(reader)
                await eventually(lambda: server.resource_count == 0)
                assert server.idle_connections == 0
                assert await failed_request(server) == 1
            finally:
                await close_writer(writer)

    run(scenario)


@pytest.mark.parametrize(
    "target",
    [
        Target("MiXeD.target.example.", 443),
        Target(IPv4Address("192.0.2.10"), 8080),
        Target(IPv6Address("2001:db8::10"), 8443),
    ],
)
def test_registered_resource_preserves_target_bound_and_coalesced_payload(target):
    async def scenario():
        prefix = b"server-first greeting\x00\xff"
        payload = bytes(range(256)) * 8192
        bound = BoundAddress(IPv6Address("2001:db8::20"), 3456)
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                business = asyncio.create_task(
                    connect_request(server, target, payload=payload)
                )
                assert await reverse_request(agent_reader) == BoundAddress(
                    target.host, target.port
                )
                assert server.idle_count() == 0
                assert server.resource_count == 1
                agent_writer.write(encode_reply(0, bound) + prefix)
                await agent_writer.drain()
                reader, writer, reply, received_bound = await business
                try:
                    assert reply == 0 and received_bound == bound
                    assert await reader.readexactly(len(prefix)) == prefix
                    assert await agent_reader.readexactly(len(payload)) == payload
                    writer.write_eof()
                    assert await agent_reader.read() == b""
                    agent_writer.write(b"reply after half-close")
                    agent_writer.write_eof()
                    assert await reader.read() == b"reply after half-close"
                finally:
                    await close_writer(writer)
            await eventually(lambda: server.resource_count == 0)
            assert server.idle_count() == 0

    run(scenario)


@pytest.mark.parametrize("user", [None, b"", b"team-a", b"Team-A", b"\xff\x00"])
def test_only_same_raw_username_can_claim_a_resource(user):
    async def scenario():
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server, user=user, password=b"registration-secret") as (
                agent_reader,
                agent_writer,
            ):
                for other in [None, b"", b"team-a", b"Team-A", b"\xff\x00"]:
                    if other != user:
                        assert await failed_request(server, user=other) == 1
                        assert server.idle_count(user) == 1
                business = asyncio.create_task(
                    connect_request(
                        server,
                        Target("same-user.example", 443),
                        user=user,
                        password=b"different-business-secret",
                    )
                )
                assert await reverse_request(agent_reader) == BoundAddress(
                    "same-user.example", 443
                )
                agent_writer.write(encode_reply(0) + b"right pool")
                agent_writer.write_eof()
                reader, writer, reply, _bound = await business
                try:
                    assert reply == 0 and await reader.read() == b"right pool"
                    writer.write_eof()
                    assert await agent_reader.read() == b""
                finally:
                    await close_writer(writer)

    run(scenario)


def test_resource_selection_is_random_and_consumes_each_resource_once(monkeypatch):
    async def scenario():
        choices = []

        def choose_last(stop):
            choices.append(stop)
            return stop - 1

        monkeypatch.setattr(random, "randrange", choose_last)
        async with immediate_server() as server:
            await server.start(port=0)
            async with (
                resource(server) as (first_reader, first_writer),
                resource(server) as (second_reader, second_writer),
            ):
                for reader, writer in [
                    (second_reader, second_writer),
                    (first_reader, first_writer),
                ]:
                    request = asyncio.create_task(failed_request(server))
                    assert await reverse_request(reader) == BoundAddress(
                        "destination.example", 80
                    )
                    writer.write(encode_reply(5))
                    await writer.drain()
                    assert await request == 5
                    await closed(reader)
                assert await failed_request(server) == 1
            assert choices == [2, 1]
            await eventually(lambda: server.resource_count == 0)

    run(scenario)


@pytest.mark.parametrize("failure", ["rejection", "eof", "invalid", "timeout"])
def test_claimed_resource_failure_never_retries_other_idle_resources(failure):
    async def scenario():
        options = ReverseServerOptions(request_timeout=0.05)
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                business = asyncio.create_task(failed_request(server))
                await reverse_request(agent_reader)
                # Add another valid resource only after the first has been claimed.
                async with resource(server) as (spare_reader, _spare_writer):
                    if failure == "rejection":
                        agent_writer.write(b"\x05\x05\x00")
                    elif failure == "eof":
                        agent_writer.write_eof()
                    elif failure == "invalid":
                        agent_writer.write(b"\x04\x00\x00")
                    await agent_writer.drain()
                    assert await business == (5 if failure == "rejection" else 1)
                    assert server.idle_count() == 1
                    # The unused resource must receive neither CONNECT nor a close.
                    with pytest.raises(TimeoutError):
                        async with asyncio.timeout(0.02):
                            await spare_reader.read(1)
            await eventually(lambda: server.resource_count == 0)

    run(scenario)


@pytest.mark.parametrize("command", [Command.BIND, Command.UDP_ASSOCIATE, 99])
def test_unsupported_commands_do_not_consume_registered_resources(command):
    async def scenario():
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server):
                assert await failed_request(server, command=command) == 7
                assert server.idle_count() == 1

    run(scenario)


def test_registration_domain_is_case_and_trailing_dot_insensitive_port_independent():
    async def scenario():
        async with immediate_server("ReVeRsE.Example.COM.") as server:
            await server.start(port=0)
            async with resource(server, target=Target("reverse.example.com", 1234)):
                async with resource(
                    server, target=Target("REVERSE.EXAMPLE.COM.", 65535)
                ):
                    assert server.idle_count() == server.resource_count == 2

    run(scenario)


def test_idle_eof_releases_quota_and_new_registration_replaces_it():
    async def scenario():
        async with immediate_server(
            options=ReverseServerOptions(max_resources=1)
        ) as server:
            await server.start(port=0)
            async with resource(server):
                assert await failed_request(server, REGISTRATION) == 1
            await eventually(lambda: server.resource_count == 0)
            async with resource(server):
                assert server.resource_count == 1

    run(scenario)


def test_user_resource_quota_includes_claimed_resources_and_is_per_user():
    async def scenario():
        options = ReverseServerOptions(max_resources=2, max_resources_per_user=1)
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            async with resource(server, user=b"one") as (agent_reader, agent_writer):
                business = asyncio.create_task(failed_request(server, user=b"one"))
                await reverse_request(agent_reader)
                assert await failed_request(server, REGISTRATION, user=b"one") == 1
                async with resource(server, user=b"two"):
                    assert server.resource_count == 2
                    assert (
                        await failed_request(server, REGISTRATION, user=b"three") == 1
                    )
                agent_writer.write(encode_reply(5))
                assert await business == 5
            await eventually(lambda: server.resource_count == 0)
            async with resource(server, user=b"one"):
                assert server.idle_count(b"one") == 1

    run(scenario)


def test_idle_timeout_removes_resource_without_sending_keepalive_bytes():
    async def scenario():
        options = ReverseServerOptions(idle_timeout=0.03)
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            async with resource(server) as (reader, _writer):
                assert await reader.read() == b""
                await eventually(lambda: server.resource_count == 0)
                assert await failed_request(server) == 1

    run(scenario)


def test_shutdown_closes_idle_and_claimed_resources_and_reclaims_descriptors():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        server = immediate_server()
        await server.start(port=0)
        async with (
            resource(server, user=b"busy") as (busy_reader, _busy_writer),
            resource(server, user=b"idle") as (idle_reader, _idle_writer),
        ):
            request = asyncio.create_task(
                connect_request(server, Target("destination.example", 80), user=b"busy")
            )
            await reverse_request(busy_reader)
            await server.aclose()
            await server.aclose()
            assert await busy_reader.read() == await idle_reader.read() == b""
            result = await asyncio.gather(request, return_exceptions=True)
            if not isinstance(result[0], BaseException):
                await close_writer(result[0][1])
            assert server.resource_count == server.active_connections == 0
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


class LocalProxy:
    """Actual SOCKS wire boundary, forwarding only to test-controlled loopback peers."""

    def __init__(self, server, destination_port=None, *, registration_failures=0):
        self.server = server
        self.destination_port = destination_port
        self.registration_failures = registration_failures
        self.registrations = 0
        self.targets = []
        self.reject_business = None

    async def __call__(self, reader, writer):
        target = await upstream_request(reader, writer)
        if isinstance(target.host, str) and target.host.lower() == REGISTRATION.host:
            self.registrations += 1
            if self.registrations <= self.registration_failures:
                writer.write(encode_reply(1))
                await writer.drain()
                return
            remote_reader, remote_writer = await asyncio.open_connection(
                *self.server.address
            )
            try:
                remote_writer.write(b"\x05\x01\x00" + encode_connect(REGISTRATION))
                assert await remote_reader.readexactly(2) == b"\x05\x00"
                reply, bound = await downstream_reply(remote_reader)
                writer.write(encode_reply(reply, bound))
                await writer.drain()
                if reply == 0:
                    try:
                        await bridge(reader, writer, remote_reader, remote_writer)
                    except* ConnectionError:
                        pass
            finally:
                await close_writer(remote_writer)
        else:
            self.targets.append(target)
            if self.reject_business is not None:
                writer.write(encode_reply(self.reject_business))
                await writer.drain()
                return
            remote_reader, remote_writer = await asyncio.open_connection(
                "127.0.0.1", self.destination_port
            )
            try:
                writer.write(encode_reply(0, BoundAddress(IPv6Address("::1"), 4321)))
                await writer.drain()
                await bridge(reader, writer, remote_reader, remote_writer)
            finally:
                await close_writer(remote_writer)


@pytest.mark.parametrize(
    "target",
    [
        Target("target.example", 443),
        Target(IPv4Address("192.0.2.123"), 9000),
        Target(IPv6Address("2001:db8::123"), 9001),
    ],
)
def test_agent_and_server_use_proxy_for_registration_and_target_with_half_close(target):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        payload = bytes(range(256)) * 8192
        prefix = b"target speaks first\x00\xff"

        async def destination(reader, writer):
            writer.write(prefix)
            await writer.drain()
            received = await reader.read()
            assert received == payload
            writer.write(hashlib.sha256(received).digest())
            await writer.drain()

        async with Service(destination) as target_service, immediate_server() as server:
            await server.start(port=0)
            routing = LocalProxy(server, target_service.port)
            async with Service(routing) as proxy:
                agent = ReverseAgent(
                    REGISTRATION,
                    Socks5Client("127.0.0.1", proxy.port),
                    options=ReverseAgentOptions(idle_connections=1, max_connections=2),
                )
                async with agent:
                    await agent.start()
                    await eventually(lambda: server.idle_count() == 1)
                    reader, writer, reply, bound = await connect_request(server, target)
                    try:
                        assert reply == 0
                        assert bound == BoundAddress(IPv6Address("::1"), 4321)
                        assert await reader.readexactly(len(prefix)) == prefix
                        await eventually(lambda: server.idle_count() == 1)
                        assert agent.active_connections == 1
                        assert agent.connection_count == 2
                        writer.write(payload)
                        await writer.drain()
                        writer.write_eof()
                        assert await reader.read() == hashlib.sha256(payload).digest()
                    finally:
                        await close_writer(writer)
                    await eventually(lambda: agent.active_connections == 0)
                    assert routing.targets == [BoundAddress(target.host, target.port)]
                    assert routing.registrations == 2
                assert agent.connection_count == agent.active_connections == 0
                await eventually(lambda: server.resource_count == 0)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_agent_total_quota_prevents_refill_until_active_business_finishes():
    async def scenario():
        async def echo(reader, writer):
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(echo) as target_service, immediate_server() as server:
            await server.start(port=0)
            routing = LocalProxy(server, target_service.port)
            async with Service(routing) as proxy:
                agent = ReverseAgent(
                    REGISTRATION,
                    Socks5Client("127.0.0.1", proxy.port),
                    options=ReverseAgentOptions(idle_connections=1, max_connections=1),
                )
                async with agent:
                    await agent.start()
                    await eventually(lambda: server.idle_count() == 1)
                    reader, writer, reply, _bound = await connect_request(
                        server, Target("first.example", 80)
                    )
                    try:
                        assert reply == 0
                        assert await failed_request(server) == 1
                        assert agent.connection_count == agent.active_connections == 1
                        assert agent.idle_connections == 0
                        assert routing.registrations == 1
                        writer.write_eof()
                        assert await reader.read() == b""
                    finally:
                        await close_writer(writer)
                    await eventually(lambda: server.idle_count() == 1)
                    assert routing.registrations == 2
                    assert agent.connection_count == 1

    run(scenario)


def test_agent_recovers_from_registration_and_target_rejections_without_new_traffic():
    async def scenario():
        async with immediate_server() as server:
            await server.start(port=0)
            routing = LocalProxy(server, registration_failures=2)
            routing.reject_business = 5
            async with Service(routing) as proxy:
                options = ReverseAgentOptions(
                    reconnect_initial_delay=0.01,
                    reconnect_max_delay=0.02,
                    max_connections=1,
                )
                agent = ReverseAgent(
                    REGISTRATION, Socks5Client("127.0.0.1", proxy.port), options=options
                )
                async with agent:
                    await agent.start()
                    await eventually(lambda: server.idle_count() == 1)
                    assert routing.registrations == 3
                    assert await failed_request(server) == 5
                    await eventually(lambda: server.idle_count() == 1)
                    assert routing.registrations == 4
                    assert len(routing.targets) == 1

    run(scenario)
