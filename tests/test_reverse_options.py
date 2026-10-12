"""Reverse limits reject invalid policy before any sockets are opened."""

import errno
from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address

import pytest

from socks5_kit.errors import ProtocolError, RejectTarget, UpstreamRejected
from socks5_kit.protocol import ReplyCode
from socks5_kit.reverse._common import (
    DEFAULT_REVERSE_DOMAIN,
    REGISTRATION_ACK,
    REGISTRATION_HELLO,
    canonical_domain,
    failure_reply,
    validate_grace_period,
)
from socks5_kit.reverse._options import ReverseAgentOptions, ReverseServerOptions

_TIMES = [
    (ReverseServerOptions, name)
    for name in (
        "handshake_timeout",
        "request_timeout",
        "reply_timeout",
        "registration_timeout",
        "queue_timeout",
        "idle_timeout",
    )
] + [
    (ReverseAgentOptions, name)
    for name in (
        "request_timeout",
        "reply_timeout",
        "registration_timeout",
        "reconnect_initial_delay",
        "reconnect_max_delay",
    )
]
_COUNTS = [
    (ReverseServerOptions, name)
    for name in (
        "max_connections",
        "max_resources",
        "max_resources_per_user",
        "backlog",
        "splice_byte_budget",
        "splice_call_budget",
    )
] + [
    (ReverseAgentOptions, name)
    for name in (
        "idle_connections",
        "max_connections",
        "splice_byte_budget",
        "splice_call_budget",
    )
]


def test_registration_frames_and_timeout_defaults():
    assert REGISTRATION_HELLO == b"S5KR\x01\x01"
    assert REGISTRATION_ACK == b"S5KR\x01\x02"
    assert ReverseServerOptions().registration_timeout == 10
    assert ReverseAgentOptions().registration_timeout == 10
    assert ReverseServerOptions().queue_timeout == 10
    assert ReverseServerOptions().max_pending_connections == 1024


@pytest.mark.parametrize("value", [True, 1.5, "1", None])
def test_pending_limit_rejects_wrong_types(value):
    with pytest.raises(TypeError, match="max_pending_connections"):
        ReverseServerOptions(max_pending_connections=value)


def test_pending_limit_allows_zero_to_disable_queue_but_rejects_negative():
    assert ReverseServerOptions(max_pending_connections=0).max_pending_connections == 0
    with pytest.raises(ValueError, match="max_pending_connections"):
        ReverseServerOptions(max_pending_connections=-1)


def test_server_registration_timeout_preserves_existing_positional_options():
    assert ReverseServerOptions(1, 2, 3, 4, 5, 6, 7, 8, False, 9, 10) == (
        ReverseServerOptions(
            handshake_timeout=1,
            request_timeout=2,
            reply_timeout=3,
            max_connections=4,
            max_resources=5,
            max_resources_per_user=6,
            idle_timeout=7,
            backlog=8,
            ipv6_only=False,
            splice_byte_budget=9,
            splice_call_budget=10,
        )
    )


def test_agent_registration_timeout_preserves_existing_positional_options():
    assert ReverseAgentOptions(2, 3, 4, 5, 6, 7, 8, 9) == ReverseAgentOptions(
        idle_connections=2,
        max_connections=3,
        request_timeout=4,
        reply_timeout=5,
        reconnect_initial_delay=6,
        reconnect_max_delay=7,
        splice_byte_budget=8,
        splice_call_budget=9,
    )


@pytest.mark.parametrize(("options", "name"), _TIMES)
@pytest.mark.parametrize("value", [True, "1", object()])
def test_time_limits_reject_wrong_types(options, name, value):
    with pytest.raises(TypeError, match=name):
        options(**{name: value})


@pytest.mark.parametrize(("options", "name"), _TIMES)
@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_time_limits_are_positive_finite(options, name, value):
    with pytest.raises(ValueError, match=name):
        options(**{name: value})


@pytest.mark.parametrize(("options", "name"), _COUNTS)
@pytest.mark.parametrize("value", [True, 1.5, "1"])
def test_connection_and_splice_budgets_require_integers(options, name, value):
    with pytest.raises(TypeError, match=name):
        options(**{name: value})


@pytest.mark.parametrize(("options", "name"), _COUNTS)
@pytest.mark.parametrize("value", [0, -1])
def test_connection_and_splice_budgets_are_positive(options, name, value):
    with pytest.raises(ValueError, match=name):
        options(**{name: value})


def test_agent_total_budget_must_cover_requested_idle_resources():
    with pytest.raises(ValueError, match="idle_connections"):
        ReverseAgentOptions(idle_connections=2, max_connections=1)
    assert ReverseAgentOptions(idle_connections=2, max_connections=2)


def test_backoff_maximum_must_cover_initial_delay():
    with pytest.raises(ValueError, match="reconnect_max_delay"):
        ReverseAgentOptions(reconnect_initial_delay=2, reconnect_max_delay=1)
    assert ReverseAgentOptions(reconnect_initial_delay=2, reconnect_max_delay=2)


def test_optional_idle_expiry_and_per_user_limit_can_be_disabled():
    options = ReverseServerOptions(idle_timeout=None, max_resources_per_user=None)
    assert options.idle_timeout is None
    assert options.max_resources_per_user is None
    options = ReverseServerOptions(idle_timeout=30, max_resources_per_user=2)
    assert options.idle_timeout == 30
    assert options.max_resources_per_user == 2


@pytest.mark.parametrize("value", [1, 0, "true", None])
def test_ipv6_only_requires_bool(value):
    with pytest.raises(TypeError, match="ipv6_only"):
        ReverseServerOptions(ipv6_only=value)


@pytest.mark.parametrize("options", [ReverseServerOptions, ReverseAgentOptions])
def test_configuration_is_immutable(options):
    config = options()
    with pytest.raises(FrozenInstanceError):
        config.max_connections = 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (DEFAULT_REVERSE_DOMAIN, DEFAULT_REVERSE_DOMAIN),
        ("Reverse.Example.COM.", "reverse.example.com"),
        ("BÜCHER.Example", "xn--bcher-kva.example"),
        ("192.0.2.1", "192.0.2.1"),
    ],
)
def test_registration_domain_normalization(value, expected):
    assert canonical_domain(value) == expected


@pytest.mark.parametrize(
    "value", [None, True, b"reverse.test", IPv4Address("192.0.2.1")]
)
def test_registration_domain_must_be_string(value):
    with pytest.raises(TypeError, match="domain string"):
        canonical_domain(value)


@pytest.mark.parametrize("value", ["", "reverse..test", "reverse test", "reverse\x00"])
def test_registration_domain_must_be_valid_socks_name(value):
    with pytest.raises(ValueError):
        canonical_domain(value)


@pytest.mark.parametrize(
    ("error", "reply"),
    [
        (RejectTarget(), ReplyCode.NOT_ALLOWED),
        (ProtocolError("bad command", reply=7), 7),
        (UpstreamRejected(8), 8),
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), 5),
        (OSError(errno.ENETUNREACH, "no network"), 3),
        (OSError(errno.EHOSTUNREACH, "no host"), 4),
        (OSError(errno.EIO, "failure"), 1),
        (TimeoutError(), 1),
        (RuntimeError("unexpected failure"), 1),
    ],
)
def test_failures_keep_socks_reply_semantics(error, reply):
    assert failure_reply(error) == reply


@pytest.mark.parametrize("value", [0, 0.0, 0.1, 10])
def test_shutdown_grace_accepts_zero_and_positive_intervals(value):
    assert validate_grace_period(value) is None


@pytest.mark.parametrize("value", [True, None, "1"])
def test_shutdown_grace_rejects_wrong_types(value):
    with pytest.raises(TypeError, match="grace_period"):
        validate_grace_period(value)


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), -float("inf")])
def test_shutdown_grace_rejects_invalid_intervals(value):
    with pytest.raises(ValueError, match="grace_period"):
        validate_grace_period(value)
