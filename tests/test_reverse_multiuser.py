"""Multiple independent identity pools using real SOCKS authentication and TCP."""

import asyncio
import logging
import os
from collections import defaultdict

import pytest

from socks5_kit import Socks5Client, Target
from socks5_kit.protocol import encode_connect, encode_reply
from socks5_kit.reverse import ReverseAgent, ReverseAgentOptions, ReverseServer
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO
from tests.test_auth_tcp import auth_frame
from tests.test_reverse_tcp import close_writer, connect_request, eventually
from tests.test_tcp import Service, bridge, downstream_reply, run, stream_address

pytestmark = pytest.mark.tcp_loopback

REGISTRATION = Target("reverse.socks5-kit.invalid", 443)
DESTINATION = Target("destination.example", 443)


async def authenticated_request(reader, writer, *, reject=None):
    version, count = await reader.readexactly(2)
    assert version == 5
    methods = await reader.readexactly(count)
    user = password = None
    if 2 in methods:
        writer.write(b"\x05\x02")
        await writer.drain()
        version, length = await reader.readexactly(2)
        assert version == 1
        user = (await reader.readexactly(length)).decode("utf-8")
        length = (await reader.readexactly(1))[0]
        password = (await reader.readexactly(length)).decode("utf-8")
        denied = reject is not None and reject(user, password)
        writer.write(b"\x01\x01" if denied else b"\x01\x00")
        await writer.drain()
        if denied:
            return user, password, None
    else:
        assert 0 in methods
        writer.write(b"\x05\x00")
        await writer.drain()
    assert await reader.readexactly(3) == b"\x05\x01\x00"
    address = await stream_address(reader)
    return user, password, Target(address.host, address.port)


def registration_proxy(resources, attempts=None, *, reject=None):
    async def register(reader, writer):
        user, password, target = await authenticated_request(
            reader, writer, reject=reject
        )
        if attempts is not None:
            attempts.append((user, password, asyncio.get_running_loop().time()))
        if target is None:
            return
        assert target == REGISTRATION
        assert await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
        writer.write(encode_reply(0) + REGISTRATION_ACK)
        await writer.drain()
        resources[user].put_nowait((reader, writer))
        # Tests exclusively own subsequent reads from these resources.
        await asyncio.Event().wait()

    return register


def test_one_agent_registers_and_relays_independent_users_with_shared_proxy(caplog):
    async def scenario():
        observed = []
        users = [
            None,
            ("alice", "alice-private"),
            ("用户", "用户-private"),
            ("", ""),
            "shorthand",
        ]
        baseline = len(os.listdir("/proc/self/fd"))
        caplog.set_level(logging.DEBUG, logger="socks5_kit")
        async with ReverseServer() as server:
            await server.start(port=0)

            async def local_proxy(reader, writer):
                user, password, target = await authenticated_request(reader, writer)
                observed.append((user, password, target))
                if target == REGISTRATION:
                    hello = await reader.readexactly(len(REGISTRATION_HELLO))
                    assert hello == REGISTRATION_HELLO
                    upstream_reader, upstream_writer = await asyncio.open_connection(
                        *server.address
                    )
                    try:
                        if user is None:
                            upstream_writer.write(b"\x05\x01\x00")
                            assert await upstream_reader.readexactly(2) == b"\x05\x00"
                        else:
                            upstream_writer.write(b"\x05\x01\x02")
                            assert await upstream_reader.readexactly(2) == b"\x05\x02"
                            upstream_writer.write(
                                auth_frame(user.encode(), password.encode())
                            )
                            assert await upstream_reader.readexactly(2) == b"\x01\x00"
                        upstream_writer.write(encode_connect(target) + hello)
                        reply, bound = await downstream_reply(upstream_reader)
                        writer.write(encode_reply(reply, bound))
                        await writer.drain()
                        await bridge(reader, writer, upstream_reader, upstream_writer)
                    finally:
                        await close_writer(upstream_writer)
                else:
                    assert target == DESTINATION
                    writer.write(encode_reply(0))
                    await writer.drain()
                    payload = await reader.read()
                    writer.write(repr(user).encode() + b":" + payload)
                    await writer.drain()

            async with Service(local_proxy) as proxy:
                async with ReverseAgent(
                    REGISTRATION,
                    Socks5Client("127.0.0.1", proxy.port),
                    users=users,
                    options=ReverseAgentOptions(
                        idle_connections=1,
                        max_connections=2,
                        max_total_connections=10,
                    ),
                ) as agent:
                    await agent.start()
                    await eventually(lambda: agent.idle_connections == len(users))
                    assert agent.connection_count == len(users)
                    assert agent.idle_count("unknown") == 0
                    assert agent.connection_count_for("unknown") == 0
                    assert agent.active_count("unknown") == 0
                    for entry in users:
                        user = (
                            entry
                            if entry is None or isinstance(entry, str)
                            else entry[0]
                        )
                        assert agent.idle_count(user) == 1
                        assert agent.connection_count_for(user) == 1
                        assert agent.active_count(user) == 0
                        assert (
                            server.idle_count(None if user is None else user.encode())
                            == 1
                        )

                    async def business(entry):
                        user = (
                            entry
                            if entry is None or isinstance(entry, str)
                            else entry[0]
                        )
                        payload = b"only for " + repr(user).encode() + bytes(range(256))
                        reader, writer, reply, _bound = await connect_request(
                            server,
                            DESTINATION,
                            user=None if user is None else user.encode(),
                            payload=payload,
                        )
                        try:
                            assert reply == 0
                            writer.write_eof()
                            assert (
                                await reader.read()
                                == repr(user).encode() + b":" + payload
                            )
                        finally:
                            await close_writer(writer)

                    await asyncio.gather(*(business(entry) for entry in users))
                    await eventually(
                        lambda: (
                            agent.idle_connections == len(users)
                            and agent.active_connections == 0
                            and agent.connection_count == len(users)
                        )
                    )
                    for entry in users:
                        if entry is None:
                            user, password = None, None
                        elif isinstance(entry, str):
                            user, password = entry, ""
                        else:
                            user, password = entry
                        assert (user, password, REGISTRATION) in observed
                        assert (user, password, DESTINATION) in observed
                assert agent.connection_count == agent.idle_connections == 0
                assert agent.active_connections == 0
            await eventually(lambda: server.resource_count == 0)
        assert len(os.listdir("/proc/self/fd")) == baseline
        for secret in ("alice-private", "用户-private"):
            assert secret not in caplog.text
            assert all(secret not in repr(record.__dict__) for record in caplog.records)

    run(scenario)


def test_failed_user_backoff_does_not_block_healthy_user_refill():
    async def scenario():
        resources = defaultdict(asyncio.Queue)
        attempts = []
        users = [("unhealthy", "bad"), ("healthy", "good")]
        allow_unhealthy = False

        def reject(user, _password):
            return user == "unhealthy" and not allow_unhealthy

        async def egress(reader, writer):
            user, password, target = await authenticated_request(reader, writer)
            assert (user, password, target) == ("healthy", "good", DESTINATION)
            writer.write(encode_reply(0) + b"healthy target")
            await writer.drain()
            assert await reader.read() == b""

        async with (
            Service(registration_proxy(resources, attempts, reject=reject)) as proxy,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                users=users,
                options=ReverseAgentOptions(
                    max_connections=2,
                    max_total_connections=4,
                    reconnect_initial_delay=0.15,
                    reconnect_max_delay=0.15,
                ),
            ) as agent,
        ):
            await agent.start()
            await eventually(lambda: agent.idle_count("healthy") == 1)
            await eventually(
                lambda: any(user == "unhealthy" for user, _, _ in attempts)
            )
            unhealthy_before = sum(user == "unhealthy" for user, _, _ in attempts)
            reader, writer = await resources["healthy"].get()
            writer.write(encode_connect(DESTINATION))
            await writer.drain()
            reply, _bound = await downstream_reply(reader)
            assert reply == 0
            assert await reader.readexactly(14) == b"healthy target"
            await eventually(lambda: agent.idle_count("healthy") == 1)
            assert resources["healthy"].qsize() == 1
            assert agent.active_count("healthy") == 1
            assert agent.idle_count("unhealthy") == 0
            assert (
                sum(user == "unhealthy" for user, _, _ in attempts) == unhealthy_before
            )
            writer.write_eof()
            assert await reader.read() == b""
            await eventually(lambda: agent.active_count("healthy") == 0)
            allow_unhealthy = True
            await eventually(lambda: agent.idle_count("unhealthy") == 1)
            unhealthy = [when for user, _, when in attempts if user == "unhealthy"]
            assert len(unhealthy) >= 2
            assert unhealthy[1] - unhealthy[0] >= 0.13
            assert agent.idle_connections == 2

    run(scenario)


def test_per_user_limit_counts_busy_resources_without_consuming_other_user_budget():
    async def scenario():
        resources = defaultdict(asyncio.Queue)
        attempts = []

        async def egress(reader, writer):
            user, password, target = await authenticated_request(reader, writer)
            assert (user, password, target) == ("alice", "a", DESTINATION)
            writer.write(encode_reply(0))
            await writer.drain()
            assert await reader.read() == b""

        async with (
            Service(registration_proxy(resources, attempts)) as proxy,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                users=[("alice", "a"), ("bob", "b")],
                options=ReverseAgentOptions(max_connections=1),
            ) as agent,
        ):
            await agent.start()
            await eventually(lambda: agent.idle_connections == 2)
            reader, writer = await resources["alice"].get()
            writer.write(encode_connect(DESTINATION))
            await writer.drain()
            reply, _bound = await downstream_reply(reader)
            assert reply == 0
            assert agent.connection_count_for("alice") == 1
            assert agent.active_count("alice") == 1
            assert agent.idle_count("alice") == 0
            assert agent.connection_count_for("bob") == agent.idle_count("bob") == 1
            assert agent.active_count("bob") == 0
            await asyncio.sleep(0.02)
            assert len(attempts) == 2
            writer.write_eof()
            assert await reader.read() == b""
            await eventually(
                lambda: agent.idle_connections == agent.connection_count == 2
            )
            assert sum(user == "alice" for user, _, _ in attempts) == 2
            assert sum(user == "bob" for user, _, _ in attempts) == 1

    run(scenario)


def test_global_capacity_reserves_all_opening_resources_and_refills_each_user():
    async def scenario():
        resources = defaultdict(asyncio.Queue)
        attempts = []
        registrations_continue = asyncio.Event()
        egress_continue = asyncio.Event()
        opening = 0
        peak_opening = 0

        async def registration(reader, writer):
            nonlocal opening, peak_opening
            user, _password, target = await authenticated_request(reader, writer)
            assert target == REGISTRATION
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            attempts.append(user)
            opening += 1
            peak_opening = max(peak_opening, opening)
            try:
                await registrations_continue.wait()
                writer.write(encode_reply(0) + REGISTRATION_ACK)
                await writer.drain()
                resources[user].put_nowait((reader, writer))
                await asyncio.Event().wait()
            finally:
                opening -= 1

        async def egress(reader, writer):
            user, _password, target = await authenticated_request(reader, writer)
            assert user in {"alice", "bob"}
            assert target == DESTINATION
            await egress_continue.wait()
            writer.write(encode_reply(0))
            await writer.drain()
            await reader.read()

        async with (
            Service(registration) as proxy,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                users=[("alice", "a"), ("bob", "b")],
                options=ReverseAgentOptions(
                    idle_connections=2,
                    max_connections=4,
                    max_total_connections=4,
                ),
            ) as agent,
        ):
            await agent.start()
            await eventually(lambda: len(attempts) == 4)
            assert attempts.count("alice") == attempts.count("bob") == 2
            assert agent.connection_count == 4
            assert agent.idle_connections == 0
            assert agent.connection_count_for("alice") == 2
            assert agent.connection_count_for("bob") == 2
            assert peak_opening == 4
            registrations_continue.set()
            await eventually(lambda: agent.idle_connections == 4)
            busy_streams = {}
            for user in ("alice", "bob"):
                reader, writer = await resources[user].get()
                busy_streams[user] = (reader, writer)
                writer.write(encode_connect(DESTINATION))
                await writer.drain()
            await eventually(lambda: agent.active_connections == 2)
            assert agent.connection_count == 4
            assert agent.idle_count("alice") == agent.idle_count("bob") == 1
            assert len(attempts) == 4
            egress_continue.set()
            for user in ("alice", "bob"):
                reader, writer = busy_streams[user]
                reply, _bound = await downstream_reply(reader)
                assert reply == 0
                # Explicitly closing one busy stream releases one global slot.
                await close_writer(writer)
            await eventually(
                lambda: (
                    agent.idle_count("alice") == agent.idle_count("bob") == 2
                    and agent.connection_count == 4
                )
            )
            assert agent.connection_count == 4
            assert agent.idle_connections == 4
            assert attempts.count("alice") == attempts.count("bob") == 3

    run(scenario)


@pytest.mark.parametrize(
    "users",
    [
        None,
        "user",
        b"user",
        iter([None]),
        [],
        [None, None],
        [("same", "one"), ("same", "two")],
        ["same", ("same", "two")],
        [("a",)],
        [(1, "p")],
        [("u", None)],
        [("x" * 256, "p")],
        [("u", "界" * 86)],
    ],
)
def test_invalid_users_fail_before_start(users):
    with pytest.raises((TypeError, ValueError)):
        ReverseAgent(REGISTRATION, Socks5Client("127.0.0.1", 1), users=users)


@pytest.mark.parametrize("maximum", [0, -1, True, 1.5, "2"])
def test_invalid_global_limit_fails_without_io(maximum):
    with pytest.raises((TypeError, ValueError)):
        ReverseAgentOptions(max_total_connections=maximum)


def test_global_limit_must_allow_requested_idle_pool_for_each_identity():
    with pytest.raises(ValueError):
        ReverseAgent(
            REGISTRATION,
            Socks5Client("127.0.0.1", 1),
            users=[None, ("user", "pass")],
            options=ReverseAgentOptions(idle_connections=2, max_total_connections=3),
        )


@pytest.mark.parametrize(
    "method", ["idle_count", "connection_count_for", "active_count"]
)
def test_user_counter_selectors_reject_non_strings(method):
    agent = ReverseAgent(REGISTRATION, Socks5Client("127.0.0.1", 1))
    with pytest.raises(TypeError):
        getattr(agent, method)(b"user")
