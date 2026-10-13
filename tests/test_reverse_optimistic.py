"""Optimistic business admission retains reply and payload stream ownership."""

import asyncio
import errno
import os
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit import BoundAddress, Target
from socks5_kit.protocol import encode_reply
from socks5_kit.reverse import ReverseServerOptions
from tests.test_reverse_tcp import (
    OPTIMISTIC_BOUND,
    REGISTRATION,
    close_writer,
    connect_request,
    eventually,
    failed_request,
    immediate_server,
    resource,
    reverse_request,
)
from tests.test_tcp import run

pytestmark = pytest.mark.tcp_loopback


@pytest.mark.parametrize(
    "target",
    [
        Target("server-first.example", 80),
        Target(IPv4Address("192.0.2.44"), 443),
        Target(IPv6Address("2001:db8::44"), 8443),
    ],
)
def test_success_and_full_reverse_connect_do_not_wait_for_payload_or_agent_reply(
    target,
):
    async def scenario():
        banner = b"server-first banner\x00\xff"
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                # No application payload exists to trigger CONNECT or target setup.
                async with asyncio.timeout(0.3):
                    reader, writer, reply, bound = await connect_request(server, target)
                try:
                    assert (reply, bound) == (0, OPTIMISTIC_BOUND)
                    assert await reverse_request(agent_reader) == BoundAddress(
                        target.host, target.port
                    )
                    with pytest.raises(TimeoutError):
                        async with asyncio.timeout(0.02):
                            await reader.read(1)
                    agent_writer.write(
                        encode_reply(0, BoundAddress(IPv6Address("::1"), 1234)) + banner
                    )
                    agent_writer.write_eof()
                    assert await reader.read() == banner
                    writer.write_eof()
                    assert await agent_reader.read() == b""
                finally:
                    await close_writer(writer)

    run(scenario)


def test_multimegabyte_uplink_and_half_close_reach_agent_before_agent_reply():
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        payload = bytes(range(256)) * 32768
        response = b"response survives uplink EOF before negotiation finishes"
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                reader, writer, reply, bound = await connect_request(
                    server, Target("large-before-reply.example", 80)
                )
                try:
                    assert (reply, bound) == (0, OPTIMISTIC_BOUND)
                    await reverse_request(agent_reader)

                    async def send():
                        for offset in range(0, len(payload), 65536):
                            writer.write(payload[offset : offset + 65536])
                            await writer.drain()
                        writer.write_eof()

                    # This transfer is larger than socket and pipe buffering.
                    async with asyncio.timeout(3):
                        async with asyncio.TaskGroup() as group:
                            group.create_task(send())
                            receiving = group.create_task(agent_reader.read())
                    assert receiving.result() == payload
                    assert server.business_connections == server.resource_count == 1
                    agent_writer.write(encode_reply(0) + response)
                    agent_writer.write_eof()
                    assert await reader.read() == response
                    await eventually(lambda: server.resource_count == 0)
                finally:
                    await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize(
    "bound",
    [
        BoundAddress(IPv4Address("192.0.2.55"), 5555),
        BoundAddress(IPv6Address("2001:db8::55"), 5555),
        BoundAddress("MiXeD.bound.example.", 0),
    ],
)
def test_fragmented_agent_reply_is_consumed_exactly_before_coalesced_banner(bound):
    async def scenario():
        prefix = b"banner begins with SOCKS-looking bytes: \x05\x00\x00\x01"
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, agent_writer):
                reader, writer, reply, received_bound = await connect_request(
                    server, Target("fragmented-reply.example", 443)
                )
                try:
                    assert (reply, received_bound) == (0, OPTIMISTIC_BOUND)
                    await reverse_request(agent_reader)
                    frame = encode_reply(0, bound)
                    agent_writer.write(frame[:-1])
                    await agent_writer.drain()
                    with pytest.raises(TimeoutError):
                        async with asyncio.timeout(0.02):
                            await reader.read(1)
                    # The final REP byte and target banner arrive in one write.
                    agent_writer.write(frame[-1:] + prefix)
                    agent_writer.write_eof()
                    assert await reader.read() == prefix
                    writer.write_eof()
                    assert await agent_reader.read() == b""
                finally:
                    await close_writer(writer)

    run(scenario)


@pytest.mark.parametrize(
    "failure",
    ["reject", "eof", "invalid", "partial-eof", "timeout", "partial-timeout"],
)
def test_pending_agent_reply_failure_closes_once_and_reclaims_slots_without_retry(
    failure,
):
    async def scenario():
        options = ReverseServerOptions(
            request_timeout=0.04, max_resources=2, max_resources_per_user=2
        )
        baseline = len(os.listdir("/proc/self/fd"))
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            async with resource(server, user=b"same") as (agent_reader, agent_writer):
                reader, writer, reply, bound = await connect_request(
                    server, Target("failed-after-success.example", 80), user=b"same"
                )
                try:
                    assert (reply, bound) == (0, OPTIMISTIC_BOUND)
                    await reverse_request(agent_reader)
                    async with resource(server, user=b"same") as (
                        spare_reader,
                        _spare_writer,
                    ):
                        assert server.resource_count == server.slots_in_use == 2
                        if failure == "reject":
                            agent_writer.write(encode_reply(5) + b"must not leak")
                        elif failure == "invalid":
                            agent_writer.write(b"\x04\x00\x00")
                        elif failure.startswith("partial-"):
                            agent_writer.write(encode_reply(0)[:-1])
                        if failure in {"eof", "partial-eof"}:
                            agent_writer.write_eof()
                        await agent_writer.drain()
                        # The sole business reply was success; failure adds no bytes.
                        assert await reader.read() == b""
                        await eventually(lambda: server.resource_count == 1)
                        assert server.business_connections == 0
                        assert server.slots_in_use == server.slot_count(b"same") == 1
                        assert server.idle_count(b"same") == 1
                        with pytest.raises(TimeoutError):
                            async with asyncio.timeout(0.02):
                                await spare_reader.read(1)
                finally:
                    await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_pending_reply_holds_quota_until_timeout_then_allows_new_registration():
    async def scenario():
        options = ReverseServerOptions(
            request_timeout=0.1, max_resources=1, max_resources_per_user=1
        )
        async with immediate_server(options=options) as server:
            await server.start(port=0)
            async with resource(server, user=b"held") as (agent_reader, _agent_writer):
                reader, writer, reply, bound = await connect_request(
                    server, Target("quota-pending.example", 80), user=b"held"
                )
                try:
                    assert (reply, bound) == (0, OPTIMISTIC_BOUND)
                    await reverse_request(agent_reader)
                    assert server.business_connections == server.resource_count == 1
                    assert server.slots_in_use == server.slot_count(b"held") == 1
                    assert await failed_request(server, user=b"held") == 1
                    assert await failed_request(server, REGISTRATION, user=b"held") == 1
                    assert await reader.read() == b""
                    await eventually(lambda: server.slots_in_use == 0)
                finally:
                    await close_writer(writer)
            async with resource(server, user=b"replacement"):
                assert server.slots_in_use == 1

    run(scenario)


@pytest.mark.parametrize("stop", ["cancel", "shutdown"])
def test_pending_reply_cancellation_closes_both_streams_and_reclaims_descriptors(stop):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        async with immediate_server(
            options=ReverseServerOptions(request_timeout=60)
        ) as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, _agent_writer):
                registration_tasks = set(server._sessions)
                reader, writer, reply, bound = await connect_request(
                    server, Target("cancel-pending.example", 80)
                )
                try:
                    assert (reply, bound) == (0, OPTIMISTIC_BOUND)
                    await reverse_request(agent_reader)
                    if stop == "cancel":
                        business_task = next(
                            iter(server._sessions - registration_tasks)
                        )
                        business_task.cancel()
                        await asyncio.gather(business_task, return_exceptions=True)
                    else:
                        async with asyncio.timeout(0.3):
                            await server.aclose()
                    assert await reader.read() == await agent_reader.read() == b""
                    await eventually(lambda: server.active_connections == 0)
                    assert server.resource_count == server.business_connections == 0
                    assert server.slots_in_use == server.pending_connections == 0
                finally:
                    await close_writer(writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


def test_pipe_allocation_failure_precedes_optimistic_success_and_reverse_connect(
    monkeypatch,
):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        async with immediate_server() as server:
            await server.start(port=0)
            async with resource(server) as (agent_reader, _agent_writer):
                original_pipe2 = os.pipe2
                calls = 0

                def fail_second_pipe(flags):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise OSError(errno.EMFILE, "injected pipe allocation failure")
                    return original_pipe2(flags)

                monkeypatch.setattr(os, "pipe2", fail_second_pipe)
                assert await failed_request(server) == 1
                assert calls == 2
                assert await agent_reader.read() == b""
                await eventually(lambda: server.active_connections == 0)
                assert server.resource_count == server.business_connections == 0
                assert server.slots_in_use == 0
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
