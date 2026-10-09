"""Typed hosts distinguish IP literals from domain names without guessing."""

import inspect
from dataclasses import FrozenInstanceError, asdict
from ipaddress import IPv4Address, IPv6Address

import pytest

from socks5_kit.models import AddressType, BoundAddress, Target


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize(
    ("host", "kind"),
    [
        (IPv4Address("192.0.2.1"), AddressType.IPV4),
        (IPv6Address("2001:db8::1"), AddressType.IPV6),
        (IPv6Address("::ffff:192.0.2.1"), AddressType.IPV6),
        ("Example.COM", AddressType.DOMAIN),
        ("192.0.2.1", AddressType.DOMAIN),
        ("2001:db8::1", AddressType.DOMAIN),
    ],
)
def test_address_kind_follows_host_type(model, host, kind):
    address = model(host, 443)
    assert address.host == host
    assert address.kind is kind
    assert address.port == 443
    if isinstance(host, (IPv4Address, IPv6Address)):
        assert address.host is host


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize(
    ("domain", "normalized"),
    [
        ("Example.COM.", "Example.COM."),
        ("bücher.Example", "xn--bcher-kva.Example"),
        ("bücher.Example.", "xn--bcher-kva.Example."),
        ("xn--bcher-kva.Example", "xn--bcher-kva.Example"),
        ("a", "a"),
        (".".join(["a" * 63] * 4), ".".join(["a" * 63] * 4)),
    ],
)
def test_domains_keep_socks_normalization(model, domain, normalized):
    address = model(domain, 80)
    assert address.host == normalized
    assert address.kind is AddressType.DOMAIN


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize("host", [None, True, 0, 123, b"example.test", object()])
def test_other_host_types_are_rejected(model, host):
    with pytest.raises(TypeError, match="host must be"):
        model(host, 80)


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize(
    "domain",
    [
        "",
        "example test",
        "example\ttest",
        "example\ntest",
        "example\x00test",
        "example\x7ftest",
        "example..test",
        "a" * 64 + ".test",
        ".".join(["a" * 63] * 4) + ".a",
    ],
)
def test_invalid_domains_are_rejected(model, domain):
    with pytest.raises(ValueError):
        model(domain, 80)


@pytest.mark.parametrize("model", [BoundAddress, Target])
def test_ipv6_scope_ids_are_rejected(model):
    with pytest.raises(ValueError, match="scope ID"):
        model(IPv6Address("fe80::1%eth0"), 80)


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize("port", [True, False, 80.0, "80", None])
def test_ports_require_integers(model, port):
    with pytest.raises(TypeError, match="port must be an integer"):
        model("example.test", port)


@pytest.mark.parametrize("model", [BoundAddress, Target])
@pytest.mark.parametrize("port", [-1, 65536])
def test_ports_must_fit_socks_field(model, port):
    with pytest.raises(ValueError, match="port must be in"):
        model("example.test", port)


def test_bound_port_zero_and_target_nonzero_remain_distinct():
    bound = BoundAddress(IPv4Address("0.0.0.0"), 0)
    assert bound.port == 0
    with pytest.raises(ValueError, match="1..65535"):
        Target(IPv4Address("0.0.0.0"), 0)
    assert Target("example.test", 1).port == 1
    assert Target("example.test", 65535).port == 65535


@pytest.mark.parametrize("model", [BoundAddress, Target])
def test_only_host_and_port_are_constructor_fields(model):
    assert tuple(inspect.signature(model).parameters) == ("host", "port")
    assert asdict(model("example.test", 80)) == {"host": "example.test", "port": 80}
    with pytest.raises(TypeError):
        model(AddressType.DOMAIN, "example.test", 80)
    with pytest.raises(TypeError):
        model(host="example.test", port=80, kind=AddressType.DOMAIN)


@pytest.mark.parametrize("model", [BoundAddress, Target])
def test_factory_methods_have_been_removed(model):
    for factory in ("ipv4", "ipv6", "domain"):
        assert not hasattr(model, factory)


@pytest.mark.parametrize("model", [BoundAddress, Target])
def test_addresses_are_immutable_and_hashable(model):
    address = model(IPv4Address("192.0.2.1"), 80)
    assert address == model(IPv4Address("192.0.2.1"), 80)
    assert len({address, model(IPv4Address("192.0.2.1"), 80)}) == 1
    for field, value in (("host", "other.test"), ("port", 81), ("kind", 3)):
        with pytest.raises(FrozenInstanceError):
            setattr(address, field, value)


def test_target_retains_bound_address_inheritance():
    target = Target(IPv6Address("2001:db8::1"), 443)
    assert isinstance(target, BoundAddress)
    assert target != BoundAddress(target.host, target.port)


def test_socks_address_type_values_remain_protocol_values():
    assert int(AddressType.IPV4) == 1
    assert int(AddressType.DOMAIN) == 3
    assert int(AddressType.IPV6) == 4
