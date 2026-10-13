"""Bounded empty-pool queues retain TCP payload and own delivered resources."""

import asyncio
import os
import socket
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit import BoundAddress, Socks5Client, Target
from socks5_kit.protocol import encode_connect, encode_reply
from socks5_kit.reverse import ReverseAgent, ReverseServer, ReverseServerOptions
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO
from tests.test_auth_tcp import auth_frame
from tests.test_reverse_tcp import (
    OPTIMISTIC_BOUND,
    REGISTRATION,
    LocalProxy,
    close_writer,
    closed,
    connect_request,
    eventually,
    reverse_request,
)
from tests.test_tcp import Service, downstream_reply, run

pytestmark = pytest.mark.tcp_loopback


async def business(server, target, *, user=None, payload=b""):
    reader, writer = await asyncio.open_connection(*server.address)
    try:
        greeting = b"\x05\x01\x00"
        expected = b"\x05\x00"
        if user is not None:
            greeting = b"\x05\x01\x02" + auth_frame(user, b"ignored")
            expected = b"\x05\x02\x01\x00"
        writer.write(greeting + encode_connect(target) + payload)
        assert await reader.readexactly(len(expected)) == expected
        return reader, writer
    except BaseException:
        await close_writer(writer)
        raise


async def register(server, *, user=None):
    reader, writer, reply, _bound = await connect_request(
        server, REGISTRATION, user=user, payload=REGISTRATION_HELLO
    )
    try:
        assert reply == 0
        assert await reader.readexactly(len(REGISTRATION_ACK)) == REGISTRATION_ACK
        return reader, writer
    except BaseException:
        await close_writer(writer)
        raise


@pytest.mark.parametrize(
    "target",
    [
        Target("queued.example", 80),
        Target(IPv4Address("192.0.2.3"), 443),
        Target(IPv6Address("2001:db8::3"), 8080),
    ],
)
def test_waits_for_registration_and_preserves_payload_and_early_half_close(target):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        payload = bytes(range(256)) * 256
        bound = BoundAddress(IPv6Address("::1"), 1234)
        async with ReverseServer() as server:
            await server.start(port=0)
            reader, writer = await business(server, target, payload=payload)
            agent_writer = None
            try:
                writer.write_eof()
                await eventually(lambda: server.pending_connections == 1)
                assert server.active_connections == 1
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.02):
                        await reader.read(1)
                agent_reader, agent_writer = await register(server)
                assert await reverse_request(agent_reader) == BoundAddress(
                    target.host, target.port
                )
                assert server.pending_connections == server.idle_connections == 0
                assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                assert await agent_reader.read() == payload
                agent_writer.write(encode_reply(0, bound) + b"server first")
                await agent_writer.drain()
                assert await reader.readexactly(12) == b"server first"
                agent_writer.write(b"response after queued EOF")
                agent_writer.write_eof()
                assert await reader.read() == b"response after queued EOF"
                await eventually(lambda: server.resource_count == 0)
            finally:
                await close_writer(writer)
                if agent_writer is not None:
                    await close_writer(agent_writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_queue_timeout_rejects_and_later_registration_is_not_consumed():
    async def scenario():
        options = ReverseServerOptions(queue_timeout=0.04)
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            started = asyncio.get_running_loop().time()
            reader, writer = await business(server, Target("expired.example", 80))
            agent_writer = None
            try:
                await eventually(lambda: server.pending_connections == 1)
                assert (await downstream_reply(reader))[0] == 1
                assert asyncio.get_running_loop().time() - started >= 0.035
                assert await reader.read() == b""
                await eventually(lambda: server.active_connections == 0)
                assert server.pending_connections == 0
                agent_reader, agent_writer = await register(server)
                await eventually(lambda: server.idle_connections == 1)
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.02):
                        await agent_reader.read(1)
            finally:
                await close_writer(writer)
                if agent_writer is not None:
                    await close_writer(agent_writer)

    run(scenario)


def test_actual_agent_start_satisfies_cold_queued_socks_client_request():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        payload = b"sent before any reverse resource exists"

        async def echo(reader, writer):
            writer.write(b"target first:")
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()

        async with Service(echo) as destination, ReverseServer() as server:
            await server.start(port=0)
            routing = LocalProxy(server, destination.port)
            async with Service(routing) as proxy:
                client = Socks5Client(*server.address, handshake_timeout=2)
                connecting = asyncio.create_task(
                    client.connect(
                        Target("cold-start.example", 80), initial_data=payload
                    )
                )
                try:
                    await eventually(lambda: server.pending_connections == 1)
                    assert not connecting.done()
                    async with ReverseAgent(
                        REGISTRATION, Socks5Client("127.0.0.1", proxy.port)
                    ) as agent:
                        await agent.start()
                        async with await connecting as tunnel:
                            expected = b"target first:" + payload
                            received = b""
                            while len(received) < len(expected):
                                chunk = await tunnel.recv(len(expected) - len(received))
                                assert chunk
                                received += chunk
                            assert received == expected
                            assert server.pending_connections == 0
                            tunnel.shutdown_write()
                            assert await tunnel.recv() == b""
                finally:
                    connecting.cancel()
                    result = await asyncio.gather(connecting, return_exceptions=True)
                    if not isinstance(result[0], BaseException):
                        result[0].close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_requests_are_fifo_while_resources_remain_single_use():
    async def scenario():
        writers = []
        async with ReverseServer() as server:
            await server.start(port=0)
            try:
                requests = []
                for index in range(3):
                    target = Target(f"queued-{index}.example", 80)
                    reader, writer = await business(server, target)
                    writers.append(writer)
                    requests.append((reader, target))
                    await eventually(
                        lambda expected=index + 1: (
                            server.pending_connections == expected
                        )
                    )
                for index, (reader, target) in enumerate(requests):
                    agent_reader, agent_writer = await register(server)
                    writers.append(agent_writer)
                    assert await reverse_request(agent_reader) == BoundAddress(
                        target.host, target.port
                    )
                    assert server.pending_connections == 2 - index
                    agent_writer.write(encode_reply(5))
                    await agent_writer.drain()
                    assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                    assert await reader.read() == b""
                    await eventually(lambda: server.resource_count == 0)
                assert server.pending_connections == 0
            finally:
                for writer in writers:
                    await close_writer(writer)

    run(scenario)


@pytest.mark.parametrize("user", [None, b""])
def test_waiting_request_cannot_consume_another_users_registration(user):
    async def scenario():
        writers = []
        async with ReverseServer() as server:
            await server.start(port=0)
            try:
                reader, writer = await business(
                    server, Target("isolated.example", 80), user=user
                )
                writers.append(writer)
                await eventually(lambda: server.pending_connections == 1)
                other_reader, other_writer = await register(server, user=b"other")
                writers.append(other_writer)
                assert server.idle_count(b"other") == 1
                assert server.pending_connections == 1
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.02):
                        await other_reader.read(1)
                agent_reader, agent_writer = await register(server, user=user)
                writers.append(agent_writer)
                assert await reverse_request(agent_reader) == BoundAddress(
                    "isolated.example", 80
                )
                agent_writer.write(encode_reply(5))
                await agent_writer.drain()
                assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                assert await reader.read() == b""
                assert server.pending_connections == 0
                assert server.idle_count(b"other") == 1
            finally:
                for writer in writers:
                    await close_writer(writer)

    run(scenario)


def test_queue_capacity_is_global_and_full_queue_rejects_without_waiting():
    async def scenario():
        options = ReverseServerOptions(queue_timeout=1, max_pending_connections=1)
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            first_reader, first_writer = await business(
                server, Target("first.example", 80), user=b"first"
            )
            second_writer = None
            try:
                await eventually(lambda: server.pending_connections == 1)
                second_reader, second_writer = await business(
                    server, Target("second.example", 80), user=b"second"
                )
                async with asyncio.timeout(0.2):
                    assert (await downstream_reply(second_reader))[0] == 1
                    assert await second_reader.read() == b""
                assert server.pending_connections == 1
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(0.02):
                        await first_reader.read(1)
            finally:
                await close_writer(first_writer)
                if second_writer is not None:
                    await close_writer(second_writer)

    run(scenario)


def test_waiters_count_toward_connection_cap_and_leave_room_for_registration():
    async def scenario():
        options = ReverseServerOptions(
            queue_timeout=1, max_connections=3, max_pending_connections=99
        )
        writers = []
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            try:
                for index in range(2):
                    _reader, writer = await business(
                        server, Target(f"capacity-{index}.example", 80)
                    )
                    writers.append(writer)
                    await eventually(
                        lambda expected=index + 1: (
                            server.pending_connections == expected
                        )
                    )
                reader, writer = await business(server, Target("overflow.example", 80))
                writers.append(writer)
                assert (await downstream_reply(reader))[0] == 1
                await eventually(lambda: server.active_connections == 2)

                agent_reader, agent_writer = await register(server)
                writers.append(agent_writer)
                assert await reverse_request(agent_reader) == BoundAddress(
                    "capacity-0.example", 80
                )
                assert server.pending_connections == 1
                assert server.active_connections == 3
                extra_reader, extra_writer = await asyncio.open_connection(
                    *server.address
                )
                writers.append(extra_writer)
                extra_writer.write(b"\x05\x01\x00")
                await closed(extra_reader)
                assert server.active_connections == 3
            finally:
                for writer in writers:
                    await close_writer(writer)

    run(scenario)


def test_cancelled_waiter_is_removed_before_another_request_gets_resource():
    async def scenario():
        writers = []
        async with ReverseServer() as server:
            await server.start(port=0)
            try:
                first_reader, first_writer = await business(
                    server, Target("cancelled.example", 80)
                )
                writers.append(first_writer)
                await eventually(lambda: server.pending_connections == 1)
                first_task = next(iter(server._sessions))
                reader, writer = await business(server, Target("survivor.example", 80))
                writers.append(writer)
                await eventually(lambda: server.pending_connections == 2)
                first_task.cancel()
                await asyncio.gather(first_task, return_exceptions=True)
                assert await first_reader.read() == b""
                assert server.pending_connections == 1
                agent_reader, agent_writer = await register(server)
                writers.append(agent_writer)
                assert await reverse_request(agent_reader) == BoundAddress(
                    "survivor.example", 80
                )
                agent_writer.write(encode_reply(5))
                await agent_writer.drain()
                assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                assert await reader.read() == b""
                assert server.pending_connections == 0
            finally:
                for writer in writers:
                    await close_writer(writer)

    run(scenario)


def test_graceful_shutdown_closes_waiters_immediately_and_reclaims_fds():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        writers = []
        readers = []
        async with ReverseServer(
            options=ReverseServerOptions(queue_timeout=60)
        ) as server:
            await server.start(port=0)
            try:
                for index in range(3):
                    reader, writer = await business(
                        server, Target(f"shutdown-{index}.example", 80)
                    )
                    readers.append(reader)
                    writers.append(writer)
                await eventually(lambda: server.pending_connections == 3)
                async with asyncio.timeout(0.3):
                    await server.aclose(grace_period=5)
                assert server.pending_connections == server.active_connections == 0
                for reader in readers:
                    assert await reader.read() == b""
            finally:
                for writer in writers:
                    await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize("delivered", [False, True])
def test_cancel_racing_resource_delivery_preserves_ownership(delivered):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        async with ReverseServer() as server:
            await server.start(port=0)
            waiting = asyncio.create_task(server._wait_for_resource(None))
            await eventually(lambda: server.pending_connections == 1)
            connection, peer = socket.socketpair()
            try:
                connection.setblocking(False)
                resource = server._reserve(connection, None)
                if not delivered:
                    pending = next(iter(server._pending[None]))
                    pending.ready.cancel()
                server._publish(resource)
                if delivered:
                    assert resource.state == "claimed"
                    waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting
                assert server.pending_connections == 0
                if delivered:
                    assert connection.fileno() == -1
                    assert server.resource_count == 0
                else:
                    assert server.resource_count == server.idle_connections == 1
            finally:
                waiting.cancel()
                await asyncio.gather(waiting, return_exceptions=True)
                peer.close()
                for resource in tuple(server._resources):
                    server._retire(resource)
                connection.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
