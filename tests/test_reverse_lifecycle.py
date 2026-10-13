"""Graceful relay shutdown and deterministic idle-resource ownership races."""

import asyncio
import os
import random
import socket

import pytest

from socks5_kit._io import read_exact
from socks5_kit.protocol import encode_reply
from socks5_kit.reverse import ReverseServerOptions
from socks5_kit.reverse._common import REGISTRATION_HELLO
from tests.test_reverse_tcp import (
    DESTINATION,
    REGISTRATION,
    close_writer,
    connect_request,
    eventually,
    failed_request,
    immediate_server,
    resource,
    reverse_request,
    success_then_closed,
)
from tests.test_tcp import run

pytestmark = pytest.mark.tcp_loopback


@pytest.mark.parametrize("partial_hello", [b"", REGISTRATION_HELLO[:3]])
def test_graceful_shutdown_closes_pending_registration_without_waiting_for_hello(
    partial_hello,
):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        server = immediate_server(options=ReverseServerOptions(max_resources=1))
        await server.start(port=0)
        reader, writer, reply, _bound = await connect_request(
            server, REGISTRATION, payload=partial_hello
        )
        try:
            assert reply == 0
            assert server.resource_count == server.active_connections == 1
            assert server.idle_connections == 0
            async with asyncio.timeout(0.3):
                await server.aclose(grace_period=5)
            assert await reader.read() == b""
            assert server.resource_count == server.active_connections == 0
        finally:
            await server.aclose()
            await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_cancelled_registration_handler_releases_pending_user_reservation():
    async def scenario():
        options = ReverseServerOptions(max_resources=1, max_resources_per_user=1)
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(
                server, REGISTRATION, user=b"cancelled", payload=REGISTRATION_HELLO[:3]
            )
            try:
                assert reply == 0
                assert server.resource_count == 1
                assert server.idle_connections == 0
                pending = tuple(server._sessions)
                assert len(pending) == 1
                pending[0].cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                assert await reader.read() == b""
                assert server.resource_count == server.idle_connections == 0
                async with resource(server, user=b"cancelled"):
                    assert server.resource_count == server.idle_connections == 1
            finally:
                await close_writer(writer)

    run(scenario)


@pytest.mark.parametrize("cancel_close", [False, True])
def test_server_grace_keeps_relay_live_and_cancelled_close_reclaims_fds(cancel_close):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                business = asyncio.create_task(connect_request(server, DESTINATION))
                await reverse_request(agent_reader)
                agent_writer.write(encode_reply(0))
                await agent_writer.drain()
                reader, writer, reply, _bound = await business
                try:
                    assert reply == 0
                    closing = asyncio.create_task(
                        server.aclose(grace_period=0.15 if cancel_close else 1)
                    )
                    await eventually(lambda: server._listener is None)
                    assert not closing.done()
                    assert server.resource_count == 1
                    assert server.active_connections == 2

                    # The registration handler must retain the claimed socket
                    # while the business handler forwards bytes during grace.
                    writer.write(b"during grace")
                    await writer.drain()
                    assert await agent_reader.readexactly(12) == b"during grace"
                    agent_writer.write(b"still live")
                    await agent_writer.drain()
                    assert await reader.readexactly(10) == b"still live"

                    if cancel_close:
                        closing.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await closing
                        assert await reader.read() == b""
                        assert await agent_reader.read() == b""
                    else:
                        writer.write_eof()
                        assert await agent_reader.read() == b""
                        agent_writer.write(b"final after EOF")
                        agent_writer.write_eof()
                        assert await reader.read() == b"final after EOF"
                        await closing
                    assert server.resource_count == server.active_connections == 0
                finally:
                    await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_idle_removal_updates_index_of_resource_swapped_from_pool_end(monkeypatch):
    async def scenario():
        monkeypatch.setattr(random, "randrange", lambda _stop: 0)
        async with immediate_server() as server:
            await server.start(port=0)
            async with (
                resource(server) as (_first_reader, first_writer),
                resource(server) as (_second_reader, second_writer),
                resource(server) as (third_reader, third_writer),
            ):
                # Retire index zero; the last resource must inherit that index.
                await close_writer(first_writer)
                await eventually(lambda: server.resource_count == 2)
                business = asyncio.create_task(success_then_closed(server))
                await reverse_request(third_reader)
                third_writer.write(encode_reply(5))
                await third_writer.drain()
                await business
                await eventually(lambda: server.resource_count == 1)

                # Claiming the swapped resource swaps the second resource too.
                # Its subsequent EOF must remove the final idle pool entry.
                await close_writer(second_writer)
                await eventually(lambda: server.resource_count == 0)
                assert server.idle_connections == 0
                assert await failed_request(server) == 1

    run(scenario)


@pytest.mark.parametrize("stale_kind", ["eof", "unsolicited"])
def test_selection_skips_ready_stale_resource_and_old_watcher_cannot_steal_io(
    stale_kind, monkeypatch
):
    async def scenario():
        monkeypatch.setattr(random, "randrange", lambda _stop: 0)
        async with immediate_server(
            options=ReverseServerOptions(idle_timeout=60)
        ) as server:
            await server.start(port=0)
            stale_socket, stale_peer = socket.socketpair()
            healthy_socket, healthy_peer = socket.socketpair()
            received = None
            try:
                for connection in (stale_socket, healthy_socket):
                    connection.setblocking(False)
                stale = server._reserve(stale_socket, None)
                healthy = server._reserve(healthy_socket, None)
                server._publish(stale)
                server._publish(healthy)

                # Do not yield: readiness arrives before the idle FD callback
                # can run, so selection itself must discard the stale stream.
                if stale_kind == "eof":
                    stale_peer.shutdown(socket.SHUT_WR)
                else:
                    stale_peer.sendall(b"unexpected agent bytes")
                assert server._take(None) is healthy
                assert stale_socket.fileno() == -1
                assert stale.done.done()
                assert server.resource_count == 1
                assert server.idle_connections == 0
                assert not healthy.watching
                assert healthy.timer is None

                payload = encode_reply(0) + b"coalesced business bytes"
                received = asyncio.create_task(read_exact(healthy_socket, len(payload)))
                await asyncio.sleep(0)
                # Model callbacks already queued by the old idle watcher. A
                # new socket reader now owns the FD and the incoming reply.
                loop = asyncio.get_running_loop()
                loop.call_soon(server._idle_readable, stale)
                loop.call_soon(server._idle_readable, healthy)
                healthy_peer.sendall(payload)
                assert await received == payload
                assert server.resource_count == 1
            finally:
                if received is not None:
                    received.cancel()
                    await asyncio.gather(received, return_exceptions=True)
                stale_peer.close()
                healthy_peer.close()
                # Also close sockets if setup failed before reserving them.
                for registered in tuple(server._resources):
                    server._retire(registered)
                stale_socket.close()
                healthy_socket.close()

    run(scenario)
