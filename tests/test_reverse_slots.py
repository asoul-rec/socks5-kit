"""Registrations and admitted business share user-owned resource quota slots."""

import asyncio
import os

import pytest

from socks5_kit import BoundAddress, Target
from socks5_kit.protocol import encode_reply
from socks5_kit.reverse import ReverseServer, ReverseServerOptions
from tests.test_reverse_queue import business, register
from tests.test_reverse_tcp import (
    OPTIMISTIC_BOUND,
    REGISTRATION,
    close_writer,
    connect_request,
    eventually,
    reverse_request,
)
from tests.test_tcp import downstream_reply, run

pytestmark = pytest.mark.tcp_loopback


async def rejected(server, target, *, user=None):
    # A quota rejection must not enter the one-second resource wait queue.
    async with asyncio.timeout(0.2):
        reader, writer, reply, _bound = await connect_request(server, target, user=user)
        try:
            assert reply == 1
            assert await reader.read() == b""
        finally:
            await close_writer(writer)


@pytest.mark.parametrize("quota", [2, 32])
def test_burst_reserves_business_slots_before_queueing_and_rejects_overflow(quota):
    async def scenario():
        options = ReverseServerOptions(
            max_resources=128, max_resources_per_user=quota, queue_timeout=1
        )
        writers = []
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            try:
                for index in range(quota):
                    _reader, writer = await business(
                        server, Target(f"burst-{index}.example", 80), user=b"burst"
                    )
                    writers.append(writer)
                await eventually(lambda: server.pending_connections == quota)
                assert server.business_connections == server.slots_in_use == quota
                assert server.resource_count == 0
                assert server.slot_count(b"burst") == quota
                await rejected(server, Target("overflow.example", 80), user=b"burst")
                assert (
                    server.pending_connections == server.business_connections == quota
                )
                assert server.slots_in_use == quota
            finally:
                for writer in writers:
                    await close_writer(writer)
        assert server.slots_in_use == server.business_connections == 0
        assert server.slot_count(b"burst") == 0

    run(scenario)


@pytest.mark.parametrize("registrations_first", [False, True])
def test_both_arrival_orders_pair_within_full_quota_without_double_counting(
    registrations_first,
):
    async def scenario():
        options = ReverseServerOptions(
            max_resources=2, max_resources_per_user=2, queue_timeout=1
        )
        target = Target("paired.example", 80)
        writers = []
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            try:
                agents = []
                requests = []
                if registrations_first:
                    for _ in range(2):
                        agent_reader, agent_writer = await register(
                            server, user=b"same"
                        )
                        agents.append((agent_reader, agent_writer))
                        writers.append(agent_writer)
                    assert server.resource_count == server.slots_in_use == 2
                for _ in range(2):
                    reader, writer = await business(server, target, user=b"same")
                    requests.append(reader)
                    writers.append(writer)
                await eventually(lambda: server.business_connections == 2)
                assert server.slots_in_use == server.slot_count(b"same") == 2
                if not registrations_first:
                    assert server.pending_connections == 2
                    for _ in range(2):
                        agent_reader, agent_writer = await register(
                            server, user=b"same"
                        )
                        agents.append((agent_reader, agent_writer))
                        writers.append(agent_writer)
                for reader, _writer in agents:
                    assert await reverse_request(reader) == BoundAddress(
                        target.host, target.port
                    )
                assert server.pending_connections == 0
                assert server.resource_count == server.business_connections == 2
                assert server.slots_in_use == 2
                await rejected(server, target, user=b"same")
                await rejected(server, REGISTRATION, user=b"same")
                # Success precedes target negotiation; claimed slots stay held.
                for reader in requests:
                    assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                await rejected(server, target, user=b"same")
                for _reader, writer in agents:
                    writer.write(encode_reply(0))
                    await writer.drain()
                assert server.slots_in_use == server.business_connections == 2
                await rejected(server, target, user=b"same")
                await server.aclose()
                assert server.slots_in_use == server.business_connections == 0
                assert server.resource_count == server.pending_connections == 0
            finally:
                for writer in writers:
                    await close_writer(writer)

    run(scenario)


def test_global_quota_sums_each_user_max_instead_of_cross_user_offset():
    async def scenario():
        options = ReverseServerOptions(max_resources=2, queue_timeout=1)
        writers = []
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            try:
                agent_reader, agent_writer = await register(server, user=b"registered")
                writers.append(agent_writer)
                _reader, writer = await business(
                    server, Target("waiting.example", 80), user=b"waiting"
                )
                writers.append(writer)
                await eventually(lambda: server.pending_connections == 1)
                assert server.resource_count == server.business_connections == 1
                assert server.slot_count(b"registered") == 1
                assert server.slot_count(b"waiting") == 1
                assert server.slots_in_use == 2
                await rejected(server, Target("extra.example", 80), user=b"third")
                await rejected(server, REGISTRATION, user=b"third")
                assert server.slots_in_use == 2
                # Each of the existing groups can attach its missing side even
                # while all global slots are already occupied.
                reader, writer = await business(
                    server, Target("matching.example", 80), user=b"registered"
                )
                writers.append(writer)
                assert await reverse_request(agent_reader) == BoundAddress(
                    "matching.example", 80
                )
                waiting_reader, waiting_writer = await register(server, user=b"waiting")
                writers.append(waiting_writer)
                assert await reverse_request(waiting_reader) == BoundAddress(
                    "waiting.example", 80
                )
                assert server.resource_count == server.business_connections == 2
                assert server.slots_in_use == 2
                assert server.pending_connections == 0
            finally:
                for writer in writers:
                    await close_writer(writer)
        assert server.slots_in_use == 0

    run(scenario)


@pytest.mark.parametrize("release", ["timeout", "cancel", "queue-full"])
def test_failed_business_admission_releases_slot_for_other_user(release):
    async def scenario():
        options = ReverseServerOptions(
            max_resources=1,
            max_resources_per_user=1,
            queue_timeout=0.04 if release == "timeout" else 1,
            max_pending_connections=0 if release == "queue-full" else 1024,
        )
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            reader, writer = await business(
                server, Target("will-close.example", 80), user=b"first"
            )
            agent_writer = None
            try:
                if release == "cancel":
                    await eventually(lambda: server.pending_connections == 1)
                    task = next(iter(server._sessions))
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                else:
                    assert (await downstream_reply(reader))[0] == 1
                assert await reader.read() == b""
                await eventually(lambda: server.business_connections == 0)
                assert server.slots_in_use == server.slot_count(b"first") == 0
                _agent_reader, agent_writer = await register(server, user=b"second")
                assert server.slot_count(b"second") == server.slots_in_use == 1
            finally:
                await close_writer(writer)
                if agent_writer is not None:
                    await close_writer(agent_writer)

    run(scenario)


def test_cancel_after_queue_delivery_releases_both_sides_and_descriptors(monkeypatch):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        options = ReverseServerOptions(max_resources=1, max_resources_per_user=1)
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            reader, writer = await business(
                server, Target("cancel-delivery.example", 80), user=b"first"
            )
            agent_writer = None
            try:
                await eventually(lambda: server.pending_connections == 1)
                business_task = next(iter(server._sessions))
                original = server._dispatch_pending

                def dispatch_then_cancel(user):
                    original(user)
                    business_task.cancel()

                monkeypatch.setattr(server, "_dispatch_pending", dispatch_then_cancel)
                _agent_reader, agent_writer = await register(server, user=b"first")
                await asyncio.gather(business_task, return_exceptions=True)
                assert await reader.read() == b""
                await eventually(lambda: server.active_connections == 0)
                assert server.slots_in_use == server.business_connections == 0
                assert server.resource_count == server.pending_connections == 0
                assert server.slot_count(b"first") == 0
            finally:
                await close_writer(writer)
                if agent_writer is not None:
                    await close_writer(agent_writer)
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
