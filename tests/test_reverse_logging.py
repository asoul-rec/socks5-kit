"""Access logs describe real reverse milestones and pool bottlenecks."""

import asyncio
import logging

import pytest

from socks5_kit import BoundAddress, Socks5Client, Target
from socks5_kit.protocol import encode_connect, encode_reply
from socks5_kit.reverse import (
    ReverseAgent,
    ReverseAgentOptions,
    ReverseServer,
    ReverseServerOptions,
)
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO
from tests.test_reverse_queue import business, register
from tests.test_reverse_tcp import (
    OPTIMISTIC_BOUND,
    REGISTRATION,
    close_writer,
    connect_request,
    eventually,
    reverse_request,
)
from tests.test_tcp import Service, downstream_reply, run, upstream_request

pytestmark = pytest.mark.tcp_loopback
SERVER_LOGGER = "socks5_kit.reverse._server"
AGENT_LOGGER = "socks5_kit.reverse._agent"
LOG_FIELDS = set(
    "event server_id agent_id connection_id resource_id user peer target "
    "registration_target proxy egress_proxy stage reason error_type elapsed_ms "
    "wait_ms idle_ms duration_ms reply_code decision spawn_count idle opening busy "
    "total desired_idle resources business pending slots user_idle user_resources "
    "user_business user_pending user_slots connections max_connections max_resources "
    "max_resources_per_user max_pending_connections queue_timeout queue_limit "
    "retry_in_ms user_count global_total max_total_connections".split()
)


def events(caplog, event, *, logger=None):
    return [
        record
        for record in caplog.records
        if getattr(record, "event", None) == event
        and (logger is None or record.name == logger)
    ]


def assert_event_fields(record, *fields):
    """Messages and structured handlers must see the same relevant fields."""
    standard = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
    expected = {"event", *fields}
    assert set(vars(record)) - standard == expected
    message_fields = {
        token.split("=", 1)[0]
        for token in record.getMessage().split()
        if "=" in token and token.split("=", 1)[0] in LOG_FIELDS
    }
    assert message_fields == expected


SERVER_BUSINESS_FIELDS = ("server_id", "connection_id", "user", "target")
SERVER_RESOURCE_FIELDS = (*SERVER_BUSINESS_FIELDS, "resource_id")
AGENT_RESOURCE_FIELDS = ("agent_id", "resource_id", "user")


def assert_no_secrets(caplog, *secrets):
    # Check formatted messages and structured extras: logging adapters may
    # render either, and credentials or application bytes belong in neither.
    rendered = "\n".join(
        record.getMessage() + repr(vars(record)) for record in caplog.records
    )
    for secret in secrets:
        assert secret.decode() not in rendered


def test_registration_access_log_requires_complete_hello_and_real_ack(caplog):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        user = b"registered-user"
        password = b"never-log-registration-password"
        async with ReverseServer() as server:
            await server.start(port=0)
            reader, writer, reply, _bound = await connect_request(
                server, REGISTRATION, user=user, password=password
            )
            try:
                assert reply == 0
                # The ordinary SOCKS success does not establish readiness.
                assert not events(caplog, "reverse_registered")
                assert server.resource_count == 1
                assert server.idle_connections == 0
                writer.write(REGISTRATION_HELLO)
                await writer.drain()
                assert (
                    await reader.readexactly(len(REGISTRATION_ACK)) == REGISTRATION_ACK
                )
                await eventually(lambda: bool(events(caplog, "reverse_registered")))
                record = events(caplog, "reverse_registered")[0]
                assert record.name == SERVER_LOGGER
                assert record.levelno == logging.INFO
                assert record.user == user
                assert record.target == REGISTRATION
                assert record.connection_id is not None
                assert record.resource_id is not None
                assert record.elapsed_ms >= 0
                assert_event_fields(record, *SERVER_RESOURCE_FIELDS, "elapsed_ms")
                assert server.idle_connections == server.resource_count == 1
                assert server.slots_in_use == 1
                assert server.pending_connections == server.business_connections == 0
                assert_no_secrets(caplog, password)
            finally:
                await close_writer(writer)
            await eventually(lambda: server.resource_count == server.slots_in_use == 0)

    run(scenario)


def test_queue_claim_and_actual_target_success_have_correlated_access_logs(caplog):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        target = Target("queued-observability.example", 443)
        user = b"blue"
        payload = b"private-business-payload-not-for-logs"
        options = ReverseServerOptions(max_resources=1, max_resources_per_user=1)
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            reader, writer = await business(server, target, user=user, payload=payload)
            agent_writer = None
            try:
                await eventually(lambda: server.pending_connections == 1)
                queued = events(caplog, "reverse_business_queued")[0]
                requested = events(caplog, "reverse_business_requested")[0]
                assert queued.levelno == requested.levelno == logging.INFO
                assert queued.connection_id == requested.connection_id
                assert queued.user == requested.user == user
                assert queued.target == requested.target == target
                assert_event_fields(requested, *SERVER_BUSINESS_FIELDS)
                assert_event_fields(
                    queued, *SERVER_BUSINESS_FIELDS, "user_pending", "queue_timeout"
                )
                assert queued.user_pending == 1
                assert queued.queue_timeout == options.queue_timeout
                assert server.pending_connections == server.business_connections == 1
                assert server.slots_in_use == 1
                assert server.resource_count == server.idle_connections == 0
                assert not events(caplog, "reverse_business_accepted")

                agent_reader, agent_writer = await register(server, user=user)
                assert await reverse_request(agent_reader) == BoundAddress(
                    target.host, target.port
                )
                assert await downstream_reply(reader) == (0, OPTIMISTIC_BOUND)
                assert await agent_reader.readexactly(len(payload)) == payload
                claimed = events(caplog, "reverse_resource_claimed")[0]
                accepted = events(caplog, "reverse_business_accepted")[0]
                registered = events(caplog, "reverse_registered")[0]
                assert claimed.levelno == accepted.levelno == logging.INFO
                assert claimed.wait_ms > 0
                assert claimed.connection_id == accepted.connection_id
                assert claimed.connection_id == queued.connection_id
                assert claimed.resource_id == accepted.resource_id
                assert claimed.resource_id == registered.resource_id
                assert claimed.user == accepted.user == user
                assert claimed.target == accepted.target == target
                assert_event_fields(claimed, *SERVER_RESOURCE_FIELDS, "wait_ms")
                assert_event_fields(accepted, *SERVER_RESOURCE_FIELDS, "elapsed_ms")
                assert server.pending_connections == server.idle_connections == 0
                assert server.resource_count == server.business_connections == 1
                assert server.slots_in_use == 1
                # Receiving business data proves the optimistic phase is live;
                # its success log must not claim that the Agent connected yet.
                assert not events(caplog, "reverse_target_connected")
                agent_writer.write(encode_reply(0) + b"target-banner")
                await agent_writer.drain()
                assert await reader.readexactly(13) == b"target-banner"
                connected = events(caplog, "reverse_target_connected")[0]
                assert connected.levelno == logging.INFO
                assert connected.connection_id == accepted.connection_id
                assert connected.resource_id == accepted.resource_id
                assert connected.user == user and connected.target == target
                assert connected.elapsed_ms >= 0
                assert_event_fields(connected, *SERVER_RESOURCE_FIELDS, "elapsed_ms")
                assert_no_secrets(caplog, payload)
                writer.write_eof()
                assert await agent_reader.read() == b""
                agent_writer.write_eof()
                assert await reader.read() == b""
                await eventually(
                    lambda: (
                        server.resource_count
                        == server.business_connections
                        == server.pending_connections
                        == server.slots_in_use
                        == 0
                    )
                )
            finally:
                await close_writer(writer)
                if agent_writer is not None:
                    await close_writer(agent_writer)

    run(scenario)


def test_optimistic_target_rejection_logs_failure_without_false_connected(caplog):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        target = Target("refused-observability.example", 80)
        async with ReverseServer() as server:
            await server.start(port=0)
            agent_reader, agent_writer = await register(server)
            writer = None
            try:
                reader, writer, reply, _bound = await connect_request(server, target)
                assert reply == 0
                assert await reverse_request(agent_reader) == BoundAddress(
                    target.host, target.port
                )
                accepted = events(caplog, "reverse_business_accepted")[0]
                agent_writer.write(encode_reply(5))
                await agent_writer.drain()
                assert await reader.read() == b""
                failure = events(caplog, "reverse_session_failed")[0]
                assert failure.name == SERVER_LOGGER
                assert failure.levelno == logging.WARNING
                assert failure.connection_id == accepted.connection_id
                assert failure.resource_id == accepted.resource_id
                assert failure.target == target
                assert failure.stage
                assert failure.error_type == "UpstreamRejected"
                assert_event_fields(
                    failure,
                    *SERVER_RESOURCE_FIELDS,
                    "stage",
                    "error_type",
                    "elapsed_ms",
                )
                assert not events(caplog, "reverse_target_connected")
                await eventually(
                    lambda: (
                        server.resource_count
                        == server.business_connections
                        == server.slots_in_use
                        == 0
                    )
                )
            finally:
                if writer is not None:
                    await close_writer(writer)
                await close_writer(agent_writer)

    run(scenario)


def test_queue_timeout_access_log_identifies_wait_stage_and_released_slots(caplog):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        target = Target("queue-timeout-observability.example", 443)
        options = ReverseServerOptions(queue_timeout=0.02, max_resources=1)
        async with ReverseServer(options=options) as server:
            await server.start(port=0)
            reader, writer = await business(server, target)
            try:
                assert (await downstream_reply(reader))[0] == 1
                assert await reader.read() == b""
                queued = events(caplog, "reverse_business_queued")[0]
                failure = events(caplog, "reverse_session_failed")[0]
                assert failure.levelno == logging.WARNING
                assert failure.connection_id == queued.connection_id
                assert failure.target == target
                assert failure.stage == "resource_wait"
                assert failure.error_type == "TimeoutError"
                assert failure.elapsed_ms > 0
                assert failure.wait_ms > 0
                assert failure.reply_code == 1
                assert_event_fields(
                    failure,
                    *SERVER_BUSINESS_FIELDS,
                    "stage",
                    "error_type",
                    "elapsed_ms",
                    "wait_ms",
                    "reply_code",
                )
                assert not events(caplog, "reverse_business_accepted")
                assert not events(caplog, "reverse_target_connected")
                await eventually(
                    lambda: (
                        server.business_connections
                        == server.pending_connections
                        == server.slots_in_use
                        == 0
                    )
                )
                finished = [
                    record
                    for record in events(caplog, "reverse_session_closed")
                    if record.connection_id == failure.connection_id
                ][0]
                assert_event_fields(
                    finished,
                    *SERVER_BUSINESS_FIELDS,
                    "stage",
                    "reason",
                    "elapsed_ms",
                )
            finally:
                await close_writer(writer)

    run(scenario)


def test_agent_ack_and_egress_success_logs_follow_real_handshakes(caplog):
    caplog.set_level(logging.DEBUG, logger=AGENT_LOGGER)

    async def scenario():
        registration_seen = asyncio.Event()
        allow_ack = asyncio.Event()
        resources = asyncio.Queue()
        payload_received = asyncio.Event()
        allow_target_reply = asyncio.Event()
        target = Target("agent-observability.example", 443)
        payload = b"private-egress-payload-not-for-logs"

        async def registration(reader, writer):
            requested = await upstream_request(reader, writer)
            assert requested == BoundAddress(REGISTRATION.host, REGISTRATION.port)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            writer.write(encode_reply(0))
            await writer.drain()
            registration_seen.set()
            await allow_ack.wait()
            writer.write(REGISTRATION_ACK)
            await writer.drain()
            resources.put_nowait((reader, writer))
            await asyncio.Event().wait()

        async def egress(reader, writer):
            requested = await upstream_request(reader, writer)
            assert requested == BoundAddress(target.host, target.port)
            assert await reader.readexactly(len(payload)) == payload
            payload_received.set()
            await allow_target_reply.wait()
            writer.write(encode_reply(0) + b"banner")
            await writer.drain()
            assert await reader.read() == b""
            writer.write_eof()

        async with (
            Service(registration) as carrier,
            Service(egress) as destination,
            ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", carrier.port),
                egress_proxy=Socks5Client("127.0.0.1", destination.port),
                options=ReverseAgentOptions(max_connections=1),
            ) as agent,
        ):
            await agent.start()
            started = events(caplog, "reverse_agent_started")[0]
            assert_event_fields(
                started,
                "agent_id",
                "registration_target",
                "proxy",
                "egress_proxy",
                "desired_idle",
                "max_connections",
                "user_count",
            )
            await registration_seen.wait()
            assert not events(caplog, "reverse_agent_registered")
            assert agent.idle_connections == 0
            allow_ack.set()
            reader, writer = await resources.get()
            await eventually(lambda: agent.idle_connections == 1)
            registered = events(caplog, "reverse_agent_registered")[0]
            assert registered.levelno == logging.INFO
            assert registered.resource_id is not None
            assert registered.elapsed_ms >= 0
            assert_event_fields(registered, *AGENT_RESOURCE_FIELDS, "elapsed_ms")
            writer.write(encode_connect(target) + payload)
            await writer.drain()
            await payload_received.wait()
            assert not events(caplog, "reverse_agent_target_connected")
            # With its sole resource busy, the pool cannot replenish. The
            # diagnostic must reveal capacity pressure rather than slow ACKs.
            await eventually(
                lambda: any(
                    record.busy == 1 and record.total == record.max_connections == 1
                    for record in events(caplog, "reverse_agent_pool")
                )
            )
            capacity = [
                record
                for record in events(caplog, "reverse_agent_pool")
                if record.busy == 1 and record.total == 1
            ][-1]
            assert capacity.levelno == logging.DEBUG
            assert capacity.idle == capacity.opening == 0
            assert capacity.desired_idle == 1
            assert capacity.decision
            assert_event_fields(
                capacity,
                "agent_id",
                "user",
                "decision",
                "idle",
                "opening",
                "busy",
                "total",
                "desired_idle",
                "max_connections",
            )
            allow_target_reply.set()
            assert (await downstream_reply(reader))[0] == 0
            assert await reader.readexactly(6) == b"banner"
            connected = events(caplog, "reverse_agent_target_connected")[0]
            assert connected.levelno == logging.INFO
            assert connected.resource_id == registered.resource_id
            assert connected.target == target
            assert connected.elapsed_ms >= 0
            assert_event_fields(
                connected, *AGENT_RESOURCE_FIELDS, "target", "elapsed_ms"
            )
            requested = events(caplog, "reverse_agent_business_requested")[0]
            assert_event_fields(requested, *AGENT_RESOURCE_FIELDS, "target")
            assert_no_secrets(caplog, payload)
            # Stop before releasing the consumed slot, avoiding another
            # registration in this log-correlation scenario.
            await agent.aclose()
            assert agent.connection_count == 0

    run(scenario)


def test_agent_retry_logs_explain_backoff_and_single_inflight_probe(caplog):
    caplog.set_level(logging.DEBUG, logger=AGENT_LOGGER)

    async def scenario():
        probe_opened = asyncio.Event()
        attempts = 0

        async def registration(reader, writer):
            nonlocal attempts
            await upstream_request(reader, writer)
            assert (
                await reader.readexactly(len(REGISTRATION_HELLO)) == REGISTRATION_HELLO
            )
            attempts += 1
            writer.write(encode_reply(0))
            if attempts <= 3:
                writer.write(REGISTRATION_HELLO)  # Invalid ACK, causing backoff.
                await writer.drain()
                assert await reader.read() == b""
            else:
                await writer.drain()
                probe_opened.set()
                await asyncio.Event().wait()

        options = ReverseAgentOptions(
            idle_connections=3,
            max_connections=3,
            reconnect_initial_delay=0.01,
            reconnect_max_delay=0.02,
        )
        async with Service(registration) as carrier:
            async with ReverseAgent(
                REGISTRATION,
                Socks5Client("127.0.0.1", carrier.port),
                options=options,
            ) as agent:
                await agent.start()
                await probe_opened.wait()
                await eventually(
                    lambda: any(
                        record.total == record.opening == 1
                        for record in events(caplog, "reverse_agent_pool")
                    )
                )
                assert attempts == 4
                assert agent.connection_count == 1
                assert agent.idle_connections == 0
                assert len(events(caplog, "reverse_agent_retry_scheduled")) == 3
                for record in events(caplog, "reverse_agent_retry_scheduled"):
                    assert record.levelno == logging.INFO
                    assert_event_fields(record, "agent_id", "user", "retry_in_ms")
                    assert record.retry_in_ms > 0
                failures = events(caplog, "reverse_agent_resource_failed")
                assert len(failures) == 3
                assert all(record.levelno == logging.WARNING for record in failures)
                assert all(record.stage for record in failures)
                assert all(record.error_type == "ProtocolError" for record in failures)
                for record in failures:
                    assert_event_fields(
                        record,
                        *AGENT_RESOURCE_FIELDS,
                        "stage",
                        "error_type",
                        "elapsed_ms",
                    )
                assert not events(caplog, "reverse_agent_registered")
                assert any(
                    getattr(record, "spawn_count", None) == 1
                    for record in events(caplog, "reverse_agent_pool")
                )
                assert any(
                    getattr(record, "retry_in_ms", 0) > 0
                    for record in events(caplog, "reverse_agent_pool")
                )

    run(scenario)


@pytest.mark.parametrize(
    ("version", "command", "reply", "level"),
    [(5, 2, 7, logging.INFO), (4, 1, 1, logging.WARNING)],
)
def test_protocol_policy_refusal_and_malformed_request_have_distinct_levels(
    caplog, version, command, reply, level
):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        async with ReverseServer() as server:
            await server.start(port=0)
            reader, writer = await asyncio.open_connection(*server.address)
            try:
                frame = encode_connect(Target("protocol-observability.example", 80))
                request = bytes([version, command]) + frame[2:]
                if version != 5:
                    # The invalid version is rejected before reading its address.
                    request = request[:3]
                writer.write(b"\x05\x01\x00" + request)
                await writer.drain()
                assert await reader.readexactly(2) == b"\x05\x00"
                assert (await downstream_reply(reader))[0] == reply
                assert await reader.read() == b""
                failure = events(caplog, "reverse_session_failed")[0]
                assert failure.levelno == level
                assert failure.error_type == "ProtocolError"
                assert failure.reply_code == reply
                assert_event_fields(
                    failure,
                    "server_id",
                    "connection_id",
                    "user",
                    "stage",
                    "error_type",
                    "reply_code",
                    "elapsed_ms",
                )
                assert not events(caplog, "reverse_business_accepted")
            finally:
                await close_writer(writer)

    run(scenario)


def test_unexpected_internal_failure_logs_error_without_exception_contents(
    caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG, logger=SERVER_LOGGER)

    async def scenario():
        secret = b"private-internal-error-message-never-log-this"
        target = Target("internal-error-observability.example", 443)

        def fail_admission(_user):
            raise RuntimeError(secret.decode())

        async with ReverseServer() as server:
            await server.start(port=0)
            monkeypatch.setattr(server, "_admit_business", fail_admission)
            reader, writer, reply, _bound = await connect_request(server, target)
            try:
                assert reply == 1
                assert await reader.read() == b""
                failure = events(caplog, "reverse_session_failed")[0]
                assert failure.levelno == logging.ERROR
                assert failure.error_type == "RuntimeError"
                assert failure.stage == "business_admission"
                assert failure.target == target
                assert_event_fields(
                    failure,
                    *SERVER_BUSINESS_FIELDS,
                    "stage",
                    "error_type",
                    "reply_code",
                    "elapsed_ms",
                )
                assert_no_secrets(caplog, secret)
                assert server.slots_in_use == server.business_connections == 0
            finally:
                await close_writer(writer)

    run(scenario)
