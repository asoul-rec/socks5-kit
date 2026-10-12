"""Agent refill, total budgets, retries, and stream ownership on real TCP."""

import asyncio
from ipaddress import IPv4Address, IPv6Address
from itertools import pairwise

import pytest

from socks5_kit import BoundAddress, Socks5Client, Target
from socks5_kit.protocol import encode_connect, encode_reply
from socks5_kit.reverse._agent import ReverseAgent
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO
from socks5_kit.reverse._options import ReverseAgentOptions
from tests.test_tcp import Service, downstream_reply, run, upstream_request

pytestmark = pytest.mark.tcp_loopback

REGISTRATION = Target("reverse.test", 443)


async def eventually(predicate):
    async with asyncio.timeout(2):
        while not predicate():  # noqa: ASYNC110 -- observe public counters only
            await asyncio.sleep(0.001)


def registration_handler(queue):
    async def register(reader, writer):
        request = await upstream_request(reader, writer)
        assert Target(request.host, request.port) == REGISTRATION
        # HELLO must reach the local proxy before its optimistic CONNECT reply.
        assert await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
        writer.write(encode_reply(0) + REGISTRATION_ACK)
        await writer.drain()
        queue.put_nowait((reader, writer))
        # The test owns this stream after negotiation; do not race its reader.
        await asyncio.Event().wait()

    return register


@pytest.mark.parametrize("maximum", [1, 2])
def test_refill_during_target_connect_obeys_total_budget(maximum):
    async def scenario():
        resources = asyncio.Queue()
        target_started = asyncio.Event()
        target_continue = asyncio.Event()
        target = Target(IPv6Address("2001:db8::123"), 4567)
        bound = BoundAddress(IPv6Address("2001:db8::456"), 1234)
        payload = b"pipelined payload before target connect succeeds"

        async def egress(reader, writer):
            requested = await upstream_request(reader, writer)
            assert Target(requested.host, requested.port) == target
            target_started.set()
            await target_continue.wait()
            writer.write(encode_reply(0, bound))
            await writer.drain()
            assert await reader.read() == payload
            writer.write(b"response after peer EOF")
            await writer.drain()

        async with (
            Service(registration_handler(resources)) as registration,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", registration.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                options=ReverseAgentOptions(max_connections=maximum),
            ) as agent,
        ):
            await agent.start()
            reader, writer = await resources.get()
            await eventually(lambda: agent.idle_connections == 1)
            writer.write(encode_connect(target) + payload)
            await writer.drain()
            await target_started.wait()
            assert agent.active_connections == 1
            if maximum == 2:
                await eventually(lambda: agent.idle_connections == 1)
                assert agent.connection_count == 2
                assert resources.qsize() == 1
            else:
                # A busy resource consumes the entire budget even though the
                # desired idle pool is now empty.
                await asyncio.sleep(0.03)
                assert resources.empty()
                assert agent.connection_count == 1
                assert agent.idle_connections == 0
            target_continue.set()
            assert await downstream_reply(reader) == (0, bound)
            writer.write_eof()
            assert await reader.read() == b"response after peer EOF"
            await eventually(
                lambda: (
                    agent.connection_count == 1
                    and agent.idle_connections == 1
                    and agent.active_connections == 0
                )
            )
            assert resources.qsize() == 1

    run(scenario)


def test_idle_has_no_request_timeout_but_partial_connect_does():
    async def scenario():
        resources = asyncio.Queue()
        async with Service(registration_handler(resources)) as registration:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", registration.port),
                options=ReverseAgentOptions(
                    request_timeout=0.03,
                    reconnect_initial_delay=1,
                    reconnect_max_delay=1,
                ),
            ) as agent:
                await agent.start()
                reader, writer = await resources.get()
                await eventually(lambda: agent.idle_connections == 1)
                await asyncio.sleep(0.06)
                assert agent.idle_connections == 1
                assert not reader.at_eof()
                writer.write(b"\x05")
                await writer.drain()
                reply, _bound = await downstream_reply(reader)
                assert reply == 1
                assert await reader.read() == b""
                await eventually(lambda: agent.connection_count == 0)

    run(scenario)


@pytest.mark.parametrize("command", [2, 3, 127])
def test_unsupported_reverse_command_is_rejected_without_egress(command):
    async def scenario():
        resources = asyncio.Queue()
        async with Service(registration_handler(resources)) as registration:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", registration.port),
                options=ReverseAgentOptions(
                    reconnect_initial_delay=1, reconnect_max_delay=1
                ),
            ) as agent:
                await agent.start()
                reader, writer = await resources.get()
                request = bytearray(encode_connect(Target("target.test", 80)))
                request[1] = command
                writer.write(request)
                await writer.drain()
                reply, _bound = await downstream_reply(reader)
                assert reply == 7
                assert await reader.read() == b""
                assert registration.connections == 1

    run(scenario)


def test_egress_failure_preserves_socks_reply_and_consumes_resource():
    async def scenario():
        resources = asyncio.Queue()

        async def refused(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(5))
            await writer.drain()

        async with (
            Service(registration_handler(resources)) as registration,
            Service(refused) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", registration.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                options=ReverseAgentOptions(max_connections=1),
            ) as agent,
        ):
            await agent.start()
            reader, writer = await resources.get()
            writer.write(encode_connect(Target("refused.test", 80)))
            await writer.drain()
            reply, _bound = await downstream_reply(reader)
            assert reply == 5
            assert await reader.read() == b""
            await resources.get()
            await eventually(lambda: agent.idle_connections == 1)
            assert agent.connection_count == 1
            assert registration.connections == 2
            assert destination.connections == 1

    run(scenario)


def test_registration_retries_with_backoff_without_business_requests():
    async def scenario():
        attempts = []
        resources = asyncio.Queue()

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            attempts.append(asyncio.get_running_loop().time())
            if len(attempts) <= 3:
                writer.write(encode_reply(1))
                await writer.drain()
            else:
                writer.write(encode_reply(0) + REGISTRATION_ACK)
                await writer.drain()
                resources.put_nowait((reader, writer))
                await reader.read()

        async with Service(registration) as proxy:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                options=ReverseAgentOptions(
                    reconnect_initial_delay=0.03, reconnect_max_delay=0.06
                ),
            ) as agent:
                await agent.start()
                await resources.get()
                await eventually(lambda: agent.idle_connections == 1)
                assert len(attempts) == 4
                gaps = [right - left for left, right in pairwise(attempts)]
                assert gaps[0] >= 0.025
                assert gaps[1] >= 0.05
                assert gaps[2] >= 0.05
                assert agent.connection_count == 1

    run(scenario)


def test_optimistic_socks_success_is_not_idle_until_fragmented_remote_ack():
    async def scenario():
        resources = asyncio.Queue()

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            writer.write(encode_reply(0))
            await writer.drain()
            resources.put_nowait((reader, writer))
            await asyncio.Event().wait()

        async with Service(registration) as proxy:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                options=ReverseAgentOptions(max_connections=1),
            ) as agent:
                await agent.start()
                _reader, writer = await resources.get()
                writer.write(REGISTRATION_ACK[:3])
                await writer.drain()
                await asyncio.sleep(0.02)
                assert agent.connection_count == 1
                assert agent.idle_connections == agent.active_connections == 0
                assert proxy.connections == 1
                writer.write(REGISTRATION_ACK[3:])
                await writer.drain()
                await eventually(lambda: agent.idle_connections == 1)

    run(scenario)


@pytest.mark.parametrize(
    ("ack", "eof"),
    [
        (b"NOPE\x01\x02", False),
        (b"S5KR\x02\x02", False),
        (REGISTRATION_HELLO, False),
        (b"", True),
        (REGISTRATION_ACK[:3], True),
        (b"", False),
        (REGISTRATION_ACK[:3], False),
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
def test_failed_registration_ack_closes_without_reverse_reply_or_idle(ack, eof):
    async def scenario():
        accepted = asyncio.Event()
        disconnected = asyncio.Event()

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            writer.write(encode_reply(0) + ack)
            await writer.drain()
            if eof:
                writer.write_eof()
            accepted.set()
            assert await reader.read() == b""
            disconnected.set()

        async with Service(registration) as proxy:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                options=ReverseAgentOptions(
                    registration_timeout=0.03,
                    reconnect_initial_delay=1,
                    reconnect_max_delay=1,
                    max_connections=1,
                ),
            ) as agent:
                await agent.start()
                await accepted.wait()
                assert agent.idle_connections == agent.active_connections == 0
                await disconnected.wait()
                await eventually(lambda: agent.connection_count == 0)
                assert agent.idle_connections == agent.active_connections == 0
                assert proxy.connections == 1

    run(scenario)


def test_bad_ack_retries_back_off_and_valid_ack_resets_backoff_before_business():
    async def scenario():
        attempts = []
        resources = asyncio.Queue()

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            attempts.append(asyncio.get_running_loop().time())
            ack = REGISTRATION_HELLO if len(attempts) <= 3 else REGISTRATION_ACK
            writer.write(encode_reply(0) + ack)
            await writer.drain()
            if len(attempts) == 4:
                resources.put_nowait((reader, writer))
            await reader.read()

        options = ReverseAgentOptions(
            reconnect_initial_delay=0.03, reconnect_max_delay=0.06
        )
        async with Service(registration) as proxy:
            async with ReverseAgent(
                REGISTRATION, Socks5Client("127.0.0.1", proxy.port), options=options
            ) as agent:
                await agent.start()
                await resources.get()
                await eventually(lambda: agent.idle_connections == 1)
                gaps = [right - left for left, right in pairwise(attempts)]
                assert gaps[0] >= 0.025
                assert gaps[1] >= 0.05
                assert gaps[2] >= 0.05
                assert agent._retry_delay == options.reconnect_initial_delay
                assert agent._retry_at == 0
                assert agent.active_connections == 0

    run(scenario)


def test_successful_parallel_ack_wakes_manager_waiting_for_registration_backoff():
    async def scenario():
        attempts = 0
        failed_closed = asyncio.Event()
        second_ready = asyncio.Event()
        release_ack = asyncio.Event()
        replacement_started = asyncio.Event()

        async def registration(reader, writer):
            nonlocal attempts
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            attempts += 1
            attempt = attempts
            if attempt == 1:
                writer.write(encode_reply(0) + REGISTRATION_HELLO)
                await writer.drain()
                assert await reader.read() == b""
                failed_closed.set()
                return
            writer.write(encode_reply(0))
            await writer.drain()
            if attempt == 2:
                second_ready.set()
                await release_ack.wait()
            else:
                replacement_started.set()
            writer.write(REGISTRATION_ACK)
            await writer.drain()
            assert await reader.read() == b""

        options = ReverseAgentOptions(
            idle_connections=2,
            max_connections=2,
            reconnect_initial_delay=1,
            reconnect_max_delay=1,
        )
        async with Service(registration) as proxy:
            async with ReverseAgent(
                REGISTRATION, Socks5Client("127.0.0.1", proxy.port), options=options
            ) as agent:
                await agent.start()
                await failed_closed.wait()
                await second_ready.wait()
                # Clearing the wake event after the failed task leaves means
                # the manager has entered its pending one-second backoff wait.
                await eventually(
                    lambda: agent.connection_count == 1 and not agent._wake.is_set()
                )
                assert agent.idle_connections == 0
                assert agent._retry_at - asyncio.get_running_loop().time() > 0.5
                release_ack.set()
                async with asyncio.timeout(0.2):
                    await replacement_started.wait()
                await eventually(lambda: agent.idle_connections == 2)
                assert agent.connection_count == 2
                assert proxy.connections == 3

    run(scenario)


def test_ack_coalesced_with_reverse_connect_preserves_request_and_payload():
    async def scenario():
        target = Target("coalesced.example", 8080)
        payload = b"payload directly after the reverse CONNECT"
        bound = BoundAddress(IPv6Address("2001:db8::55"), 5555)
        completed = asyncio.Event()

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            writer.write(
                encode_reply(0) + REGISTRATION_ACK + encode_connect(target) + payload
            )
            await writer.drain()
            writer.write_eof()
            assert await downstream_reply(reader) == (0, bound)
            assert await reader.read() == b"received: " + payload
            completed.set()

        async def egress(reader, writer):
            request = await upstream_request(reader, writer)
            assert Target(request.host, request.port) == target
            writer.write(encode_reply(0, bound))
            await writer.drain()
            assert await reader.read() == payload
            writer.write(b"received: " + payload)
            await writer.drain()

        async with (
            Service(registration) as proxy,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                options=ReverseAgentOptions(max_connections=1),
            ) as agent,
        ):
            await agent.start()
            await completed.wait()
            assert destination.connections == 1

    run(scenario)


@pytest.mark.parametrize("phase", ["socks_reply", "registration_ack", "idle"])
def test_graceful_close_cancels_opening_and_idle_resources_immediately(phase):
    async def scenario():
        entered = []
        exited = []

        async def registration(reader, writer):
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            entered.append(1)
            if phase != "socks_reply":
                writer.write(
                    encode_reply(0) + (REGISTRATION_ACK if phase == "idle" else b"")
                )
                await writer.drain()
            assert await reader.read() == b""
            exited.append(1)

        async with Service(registration) as proxy:
            agent = ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", proxy.port),
                options=ReverseAgentOptions(idle_connections=3, max_connections=3),
            )
            await agent.start()
            try:
                await eventually(lambda: len(entered) == 3)
                assert agent.connection_count == 3
                if phase == "idle":
                    await eventually(lambda: agent.idle_connections == 3)
                else:
                    assert agent.idle_connections == agent.active_connections == 0
                # Grace applies only to business streams, never spare resources.
                async with asyncio.timeout(0.3):
                    await agent.aclose(grace_period=5)
                assert agent.connection_count == 0
                assert agent.idle_connections == 0
                await eventually(lambda: len(exited) == 3)
            finally:
                await agent.aclose()

    run(scenario)


@pytest.mark.parametrize("cancel_close", [False, True])
def test_shutdown_grace_and_cancelled_caller_finish_active_resource_cleanup(
    cancel_close,
):
    async def scenario():
        resources = asyncio.Queue()
        destination_closed = asyncio.Event()

        async def egress(reader, writer):
            await upstream_request(reader, writer)
            writer.write(encode_reply(0))
            await writer.drain()
            assert await reader.read() == b""
            writer.write(b"final")
            await writer.drain()
            destination_closed.set()

        async with (
            Service(registration_handler(resources)) as registration,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", registration.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                options=ReverseAgentOptions(max_connections=1),
            ) as agent,
        ):
            await agent.start()
            reader, writer = await resources.get()
            writer.write(encode_connect(Target("target.test", 80)))
            await writer.drain()
            assert (await downstream_reply(reader))[0] == 0
            closing = asyncio.create_task(agent.aclose(grace_period=0.06))
            await asyncio.sleep(0)
            assert agent.active_connections == 1
            if cancel_close:
                closing.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await closing
                assert await reader.read() == b""
            else:
                assert not closing.done()
                writer.write_eof()
                assert await reader.read() == b"final"
                await closing
            assert agent.connection_count == 0
            await destination_closed.wait()
            assert registration.connections == 1

    run(scenario)


def test_serve_forever_cancellation_closes_idle_pool():
    async def scenario():
        resources = asyncio.Queue()
        async with Service(registration_handler(resources)) as registration:
            agent = ReverseAgent(
                REGISTRATION, Socks5Client("127.0.0.1", registration.port)
            )
            await agent.start()
            reader, _writer = await resources.get()
            serving = asyncio.create_task(agent.serve_forever())
            await asyncio.sleep(0)
            serving.cancel()
            with pytest.raises(asyncio.CancelledError):
                await serving
            assert agent.connection_count == 0
            assert await reader.read() == b""
            with pytest.raises(RuntimeError, match="only be started once"):
                await agent.start()

    run(scenario)


def test_start_then_close_before_manager_entry_does_not_open_connections():
    async def scenario():
        agent = ReverseAgent(REGISTRATION, Socks5Client("127.0.0.1", 1))
        await agent.start()
        await agent.aclose()
        assert agent.connection_count == 0
        await agent.aclose()

    run(scenario)


def test_constructor_validation_and_context_does_not_start():
    client = Socks5Client("127.0.0.1", 1)
    with pytest.raises(ValueError, match="DOMAIN"):
        ReverseAgent(Target(IPv4Address("127.0.0.1"), 1), client)
    with pytest.raises(TypeError, match="registration_target"):
        ReverseAgent("reverse.test", client)
    with pytest.raises(TypeError, match="proxy"):
        ReverseAgent(REGISTRATION, object())
    with pytest.raises(TypeError, match="egress_proxy"):
        ReverseAgent(REGISTRATION, client, egress_proxy=object())
    with pytest.raises(TypeError, match="options"):
        ReverseAgent(REGISTRATION, client, options=object())

    async def scenario():
        async with ReverseAgent(REGISTRATION, client) as agent:
            assert agent.connection_count == 0
            with pytest.raises(RuntimeError, match="start the agent"):
                await agent.serve_forever()
        with pytest.raises(RuntimeError, match="only be started once"):
            await agent.start()

    run(scenario)
