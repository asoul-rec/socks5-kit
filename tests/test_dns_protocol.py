"""DNS wire behavior, including hostile pointers and modern EDNS queries."""

import struct

import pytest

from socks5_kit._dns_protocol import (
    DnsFormatError,
    Query,
    Rcode,
    decode_upstream_address,
    encode_error,
    encode_response,
    encode_upstream_query,
    parse_query,
)


def name_wire(labels):
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def query_wire(
    labels=(b"Example", b"COM"),
    *,
    identifier=0x1234,
    flags=0x0110,
    qtype=1,
    qclass=1,
    additional=b"",
    arcount=0,
):
    return (
        struct.pack("!6H", identifier, flags, 1, 0, 0, arcount)
        + name_wire(labels)
        + struct.pack("!HH", qtype, qclass)
        + additional
    )


def opt_wire(*, size=1232, version=0, options=b"", flags=0x8000):
    return (
        b"\x00"
        + struct.pack("!HHIH", 41, size, (version << 16) | flags, len(options))
        + options
    )


def unpack_response(packet):
    """Independent uncompressed-question decoder for inspecting wire replies."""
    header = struct.unpack_from("!6H", packet)
    offset = 12
    labels = []
    while packet[offset]:
        size = packet[offset]
        assert size <= 63
        labels.append(packet[offset + 1 : offset + size + 1])
        offset += size + 1
    offset += 1
    question = struct.unpack_from("!HH", packet, offset)
    offset += 4
    records = []
    for _ in range(header[3]):
        assert packet[offset : offset + 2] == b"\xc0\x0c"
        offset += 2
        kind, rrclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        records.append((kind, rrclass, ttl, packet[offset : offset + size]))
        offset += size
    opt = None
    if header[5]:
        assert header[5] == 1
        assert packet[offset] == 0
        offset += 1
        opt = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        assert opt[3] == 0
    assert offset == len(packet)
    return header, tuple(labels), question, records, opt


@pytest.mark.parametrize(
    "labels, domain",
    [
        ((b"ExAmPlE", b"COM"), "example.com"),
        ((b"xn--fsqu00a", b"xn--0zwm56d"), "xn--fsqu00a.xn--0zwm56d"),
        ((b"_service", b"local"), "_service.local"),
        ((b"a.b\\c", b"\x00\xff\x20\x7f"), r"a\046b\092c.\000\255\032\127"),
        ((), "."),
    ],
)
def test_query_domains_normalize_case_without_losing_label_boundaries(labels, domain):
    query = parse_query(query_wire(labels))
    assert query.domain == domain
    assert query.labels == labels
    assert query.identifier == 0x1234
    assert query.opcode == 0


def test_callback_names_cannot_collide_for_binary_dot_and_escaped_text():
    names = [(b"a.b",), (b"a", b"b"), (rb"a\046b",)]
    domains = [parse_query(query_wire(labels)).domain for labels in names]
    assert len(set(domains)) == len(domains)


def test_success_uses_original_question_and_packed_ipv4_with_exact_ttl():
    query = parse_query(query_wire(flags=0x07F0))
    reply = encode_response(query, address=b"\xc0\x00\x02\x07", ttl=123)
    header, labels, question, records, opt = unpack_response(reply)
    assert header == (0x1234, 0x8510, 1, 1, 0, 0)
    assert labels == (b"Example", b"COM")
    assert question == (1, 1)
    assert records == [(1, 1, 123, b"\xc0\x00\x02\x07")]
    assert opt is None


def test_default_ttl_does_not_request_client_caching():
    _, _, _, records, _ = unpack_response(
        encode_response(parse_query(query_wire()), address=b"\x00\x00\x00\x00")
    )
    assert records == [(1, 1, 0, b"\x00\x00\x00\x00")]


@pytest.mark.parametrize("rcode", [Rcode.NXDOMAIN, Rcode.SERVFAIL, Rcode.REFUSED])
def test_negative_response_preserves_question_and_has_no_invented_records(rcode):
    header, labels, question, records, opt = unpack_response(
        encode_response(parse_query(query_wire()), rcode=rcode)
    )
    assert header[1] & 0xF == rcode
    assert bool(header[1] & 0x0400) == (rcode == Rcode.NXDOMAIN)
    assert header[2:] == (1, 0, 0, 0)
    assert labels == (b"Example", b"COM")
    assert question == (1, 1)
    assert records == []
    assert opt is None


def test_aaaa_can_receive_nodata_without_an_a_record_or_nxdomain():
    query = parse_query(query_wire(qtype=28))
    header, _, question, records, _ = unpack_response(encode_response(query))
    assert header[1] & 0xF == Rcode.NOERROR
    assert header[3] == 0
    assert question == (28, 1)
    assert records == []
    with pytest.raises(ValueError, match="IN/A"):
        encode_response(query, address=b"\xc0\x00\x02\x01")


def test_aaaa_answer_contains_exactly_sixteen_network_order_bytes():
    packed = bytes.fromhex("20010db8000000000000000000000007")
    query = parse_query(query_wire(qtype=28))
    header, labels, question, records, opt = unpack_response(
        encode_response(query, address=packed, ttl=47, udp=True)
    )
    assert header == (0x1234, 0x8510, 1, 1, 0, 0)
    assert labels == (b"Example", b"COM")
    assert question == (28, 1)
    assert records == [(28, 1, 47, packed)]
    assert opt is None


@pytest.mark.parametrize("qtype", [1, 5, 28])
@pytest.mark.parametrize(
    "target", [(b"Canonical", b"example"), (), (b"a.b\\c", b"\xff")]
)
def test_cname_can_answer_address_or_cname_queries_without_following_target(
    qtype, target
):
    query = parse_query(query_wire(qtype=qtype))
    header, labels, question, records, opt = unpack_response(
        encode_response(query, cname=target, ttl=19, udp=True)
    )
    assert header == (0x1234, 0x8510, 1, 1, 0, 0)
    assert labels == (b"Example", b"COM")
    assert question == (qtype, 1)
    assert records == [(5, 1, 19, name_wire(target))]
    assert opt is None


@pytest.mark.parametrize("edns", [False, True])
def test_maximum_question_and_cname_are_complete_on_tcp_and_truncated_on_udp(edns):
    maximum = (b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61)
    query = parse_query(
        query_wire(
            maximum,
            additional=opt_wire(size=65535) if edns else b"",
            arcount=int(edns),
        )
    )
    tcp_reply = encode_response(query, cname=maximum)
    assert len(tcp_reply) == 538 + (11 if edns else 0)
    header, _, _, records, opt = unpack_response(tcp_reply)
    assert not header[1] & 0x0200
    assert header[3] == 1
    assert records == [(5, 1, 0, name_wire(maximum))]
    assert opt == ((41, 512, 0, 0) if edns else None)

    udp_reply = encode_response(query, cname=maximum, udp=True)
    assert len(udp_reply) == 271 + (11 if edns else 0)
    header, labels, question, records, opt = unpack_response(udp_reply)
    assert header[1] == 0x8710
    assert header[2:] == (1, 0, 0, int(edns))
    assert labels == maximum
    assert question == (1, 1)
    assert records == []
    assert opt == ((41, 512, 0, 0) if edns else None)


@pytest.mark.parametrize("edns", [False, True])
def test_udp_preserves_a_complete_cname_at_the_512_byte_boundary(edns):
    maximum = (b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61)
    query = parse_query(
        query_wire(
            maximum,
            additional=opt_wire() if edns else b"",
            arcount=int(edns),
        )
    )
    target = (b"e" * 63, b"f" * 63, b"g" * 63, b"h" * (24 if edns else 35))
    reply = encode_response(query, cname=target, udp=True)
    assert len(reply) == 512
    header, _, _, records, _ = unpack_response(reply)
    assert not header[1] & 0x0200
    assert records == [(5, 1, 0, name_wire(target))]
    one_byte_longer = (*target[:-1], target[-1] + b"h")
    header, _, _, records, _ = unpack_response(
        encode_response(query, cname=one_byte_longer, udp=True)
    )
    assert header[1] & 0x0200
    assert records == []


def test_pointer_question_is_reencoded_without_dangling_request_references():
    labels = (b"MiXeD", b"example")
    encoded_name = name_wire(labels)
    # A tolerated forward pointer goes into an opaque additional RR payload.
    packet = (
        struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 1)
        + b"\xc0\x1d\x00\x01\x00\x01"
        + b"\x00"
        + struct.pack("!HHIH", 16, 1, 0, len(encoded_name))
        + encoded_name
    )
    query = parse_query(packet)
    assert query.labels == labels
    assert query.domain == "mixed.example"
    reply = encode_response(query, address=b"\xc0\x00\x02\x01")
    header, response_labels, _, records, _ = unpack_response(reply)
    assert response_labels == labels
    assert header[5] == 0
    assert records[0][3] == b"\xc0\x00\x02\x01"


@pytest.mark.parametrize(
    "qname",
    [
        b"\xc0\x0c",  # Pointer to itself.
        b"\xc0\xff",  # Pointer outside the packet.
        b"\xc0",  # Truncated pointer.
        b"\x40",  # Reserved label type.
        b"\x80",  # Reserved label type.
        b"\x05abc",  # Truncated label.
    ],
)
def test_invalid_names_cannot_loop_or_read_outside_packet(qname):
    packet = struct.pack("!6H", 9, 0, 1, 0, 0, 0) + qname
    with pytest.raises(DnsFormatError):
        parse_query(packet)


def test_indirect_pointer_cycle_is_detected():
    packet = struct.pack("!6H", 9, 0, 1, 0, 0, 0) + b"\xc0\x0e\xc0\x0c"
    with pytest.raises(DnsFormatError, match="loop"):
        parse_query(packet)


def test_maximum_domain_fits_without_truncation_and_longer_domain_is_rejected():
    maximum = (b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61)
    query = parse_query(query_wire(maximum))
    reply = encode_response(query, address=b"\xff\xff\xff\xff")
    assert len(reply) == 287
    assert unpack_response(reply)[1] == maximum
    with pytest.raises(DnsFormatError, match="255"):
        parse_query(query_wire((*maximum[:-1], b"d" * 62)))


@pytest.mark.parametrize("questions", [0, 2, 65535])
def test_only_one_question_is_accepted(questions):
    packet = struct.pack("!6H", 9, 0, questions, 0, 0, 0)
    with pytest.raises(DnsFormatError, match="one question"):
        parse_query(packet)


def test_all_prefix_truncations_of_edns_query_are_rejected_or_ignored():
    packet = query_wire(additional=opt_wire(), arcount=1)
    for size in range(len(packet)):
        if size < 12:
            assert parse_query(packet[:size]) is None
        else:
            with pytest.raises(DnsFormatError):
                parse_query(packet[:size])


def test_response_packets_are_ignored_even_if_the_body_is_malformed():
    packet = struct.pack("!6H", 9, 0x8000, 65535, 65535, 65535, 65535)
    assert parse_query(packet) is None
    assert encode_error(packet, Rcode.FORMERR) is None
    assert encode_error(b"short", Rcode.FORMERR) is None


def test_valid_edns_options_are_ignored_and_empty_opt_is_returned():
    unknown_option = struct.pack("!HH", 65001, 3) + b"abc"
    query = parse_query(
        query_wire(additional=opt_wire(options=unknown_option), arcount=1)
    )
    assert query.edns_size == 1232
    assert query.edns_version == 0
    header, _, _, records, opt = unpack_response(
        encode_response(query, address=b"\xc0\x00\x02\x01")
    )
    assert header[5] == 1
    assert len(records) == 1
    assert opt == (41, 512, 0, 0)


def test_edns_size_below_512_is_normalized():
    query = parse_query(query_wire(additional=opt_wire(size=0), arcount=1))
    assert query.edns_size == 512


def test_unsupported_edns_version_receives_extended_badvers_without_callback_answer():
    query = parse_query(query_wire(additional=opt_wire(version=3), arcount=1))
    header, _, _, records, opt = unpack_response(
        encode_response(query, address=b"\xc0\x00\x02\x01")
    )
    assert header[1] & 0xF == 0
    assert header[1] & 0x0400 == 0
    assert header[3] == 0
    assert records == []
    assert opt == (41, 512, 0x01000000, 0)


def test_badvers_discards_cname_and_address_before_validating_answer_arguments():
    query = parse_query(query_wire(additional=opt_wire(version=1), arcount=1))
    header, _, _, records, opt = unpack_response(
        encode_response(query, address=b"invalid", cname=(b"a" * 64,), udp=True)
    )
    assert header[1] & 0xF == 0
    assert not header[1] & 0x0200
    assert records == []
    assert opt == (41, 512, 0x01000000, 0)


@pytest.mark.parametrize(
    "additional, count",
    [
        (opt_wire() + opt_wire(), 2),
        (opt_wire(options=b"\x00"), 1),
        (opt_wire(options=struct.pack("!HH", 65001, 2) + b"a"), 1),
        (b"\x01a" + opt_wire(), 1),  # OPT owner must be root.
    ],
)
def test_malformed_edns_is_a_format_error(additional, count):
    with pytest.raises(DnsFormatError):
        parse_query(query_wire(additional=additional, arcount=count))


def test_opt_cannot_be_hidden_in_the_answer_section():
    packet = bytearray(query_wire(additional=opt_wire(), arcount=0))
    packet[6:8] = b"\x00\x01"
    with pytest.raises(DnsFormatError, match="additional"):
        parse_query(bytes(packet))


def test_other_resource_records_and_harmless_padding_can_be_skipped():
    record = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, 4) + b"\x03abc"
    packet = query_wire(additional=record, arcount=1) + b"\x00padding"
    query = parse_query(packet)
    assert query.domain == "example.com"
    assert query.edns_size is None


def test_header_only_error_does_not_reflect_untrusted_counts_or_bad_question():
    packet = struct.pack("!6H", 0x9876, 0x13F0, 65535, 65535, 65535, 65535)
    reply = encode_error(packet + b"bad question", Rcode.FORMERR)
    assert struct.unpack("!6H", reply) == (0x9876, 0x9111, 0, 0, 0, 0)


def test_opcode_is_preserved_for_not_implemented_reply():
    query = parse_query(query_wire(flags=0x2900))
    assert query.opcode == 5
    reply = encode_response(query, rcode=Rcode.NOTIMP)
    assert struct.unpack_from("!H", reply, 2)[0] == 0xA904


@pytest.mark.parametrize("address", [b"", b"abc", b"12345", "192.0.2.1", 123])
def test_answer_requires_exactly_four_packed_bytes(address):
    with pytest.raises(ValueError, match="four packed"):
        encode_response(parse_query(query_wire()), address=address)


@pytest.mark.parametrize("ttl", [-1, 2147483648, True, 0.5])
def test_invalid_ttl_is_rejected_without_struct_pack_errors(ttl):
    with pytest.raises(ValueError, match="TTL"):
        encode_response(parse_query(query_wire()), ttl=ttl)


def test_error_and_other_class_cannot_contain_an_ipv4_answer():
    query = parse_query(query_wire())
    with pytest.raises(ValueError, match="IN/A"):
        encode_response(query, rcode=Rcode.NXDOMAIN, address=b"1234")
    query = parse_query(query_wire(qclass=3))
    with pytest.raises(ValueError, match="IN/A"):
        encode_response(query, address=b"1234")
    with pytest.raises(ValueError, match="EDNS"):
        encode_response(query, rcode=Rcode.BADVERS)


@pytest.mark.parametrize("qtype", [1, 5, 15, 28, 255])
def test_ipv6_address_requires_a_matching_aaaa_query(qtype):
    query = parse_query(query_wire(qtype=qtype))
    if qtype == 28:
        assert unpack_response(encode_response(query, address=b"\x00" * 16))[3] == [
            (28, 1, 0, b"\x00" * 16)
        ]
    else:
        with pytest.raises(ValueError, match="IN/AAAA"):
            encode_response(query, address=b"\x00" * 16)


@pytest.mark.parametrize("qtype", [1, 5, 28])
def test_cname_cannot_coexist_with_an_address_record(qtype):
    query = parse_query(query_wire(qtype=qtype))
    with pytest.raises(ValueError, match="mutually exclusive"):
        encode_response(query, address=b"1234", cname=(b"target",))


@pytest.mark.parametrize(
    "qtype,qclass,rcode",
    [(15, 1, 0), (255, 1, 0), (1, 3, 0), (1, 1, Rcode.NXDOMAIN)],
)
def test_cname_requires_supported_successful_in_query(qtype, qclass, rcode):
    query = parse_query(query_wire(qtype=qtype, qclass=qclass))
    with pytest.raises(ValueError, match="CNAME requires"):
        encode_response(query, cname=(b"target",), rcode=rcode)


@pytest.mark.parametrize("target", [(b"",), (b"a" * 64,), ("string",), (123,)])
def test_cname_requires_valid_wire_labels(target):
    with pytest.raises(ValueError, match="labels"):
        encode_response(parse_query(query_wire()), cname=target)


def test_cname_wire_target_cannot_exceed_255_octets():
    too_long = (b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 62)
    with pytest.raises(ValueError, match="255"):
        encode_response(parse_query(query_wire()), cname=too_long)


def test_constructed_query_cannot_emit_invalid_labels():
    query = Query(0, 0, (b"a" * 64,), 1, 1)
    with pytest.raises(ValueError, match="labels"):
        encode_response(query)


def upstream_record(kind, data, *, owner=b"\xc0\x0c", rrclass=1, ttl=60):
    return owner + struct.pack("!HHIH", kind, rrclass, ttl, len(data)) + data


def upstream_response(
    *,
    labels=(b"Example", b"COM"),
    qtype=1,
    qclass=1,
    identifier=0x1234,
    flags=0x8180,
    answers=(),
    authorities=(),
    additionals=(),
):
    return (
        struct.pack(
            "!6H",
            identifier,
            flags,
            1,
            len(answers),
            len(authorities),
            len(additionals),
        )
        + name_wire(labels)
        + struct.pack("!HH", qtype, qclass)
        + b"".join(answers + authorities + additionals)
    )


def decode_upstream(packet, *, qtype=1):
    return decode_upstream_address(
        packet, identifier=0x1234, labels=(b"example", b"com"), qtype=qtype
    )


@pytest.mark.parametrize("qtype", [1, 28])
def test_upstream_query_requests_recursion_with_one_in_question(qtype):
    labels = (b"MiXeD", b"example")
    packet = encode_upstream_query(labels, qtype, 65535)
    assert struct.unpack_from("!6H", packet) == (65535, 0x0100, 1, 0, 0, 0)
    assert packet[12:] == name_wire(labels) + struct.pack("!HH", qtype, 1)


@pytest.mark.parametrize("qtype", [True, 5, 15, 0, 65536, "1", None])
def test_upstream_query_rejects_other_types(qtype):
    with pytest.raises(ValueError, match="A or AAAA"):
        encode_upstream_query((b"example",), qtype, 1)


@pytest.mark.parametrize("identifier", [True, -1, 65536, 1.5, "1", None])
def test_upstream_query_rejects_invalid_identifiers(identifier):
    with pytest.raises(ValueError, match="identifier"):
        encode_upstream_query((b"example",), 1, identifier)


@pytest.mark.parametrize(
    "labels", [None, "example", [b"example"], (b"",), (b"a" * 64,)]
)
def test_upstream_query_rejects_invalid_labels(labels):
    with pytest.raises(ValueError, match="labels"):
        encode_upstream_query(labels, 1, 1)


@pytest.mark.parametrize(
    "qtype,address",
    [(1, b"\xc0\x00\x02\x09"), (28, bytes.fromhex("20010db8" + "00" * 12))],
)
def test_upstream_returns_matching_family_from_a_compressed_answer(qtype, address):
    response = upstream_response(
        qtype=qtype, answers=(upstream_record(qtype, address),)
    )
    assert decode_upstream(response, qtype=qtype) == address


def test_upstream_cname_and_address_are_usable_without_another_query():
    response = upstream_response(
        answers=(
            upstream_record(5, name_wire((b"canonical", b"example"))),
            upstream_record(1, b"\xc0\x00\x02\x08", owner=name_wire((b"canonical",))),
            upstream_record(1, b"\xc0\x00\x02\x09"),
        )
    )
    assert decode_upstream(response) == b"\xc0\x00\x02\x08"


@pytest.mark.parametrize(
    "answers",
    [
        (),
        (upstream_record(5, b"\xc0\x0c"),),
        (upstream_record(28, b"\x00" * 16),),
        (upstream_record(1, b"1234", rrclass=3),),
        (upstream_record(16, b"opaque unknown record"),),
    ],
)
def test_upstream_without_matching_answer_does_not_resolve(answers):
    assert decode_upstream(upstream_response(answers=answers)) is None


@pytest.mark.parametrize("section", ["authorities", "additionals"])
def test_upstream_glue_is_not_an_answer(section):
    response = upstream_response(**{section: (upstream_record(1, b"1234"),)})
    assert decode_upstream(response) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"identifier": 1},
        {"flags": 0x0180},
        {"flags": 0x8380},
        {"flags": 0x8980},
        {"flags": 0x8183},
        {"labels": (b"different", b"com")},
        {"qtype": 28},
        {"qclass": 3},
    ],
)
def test_unrelated_failed_or_truncated_upstream_responses_are_ignored(changes):
    response = upstream_response(answers=(upstream_record(1, b"1234"),), **changes)
    assert decode_upstream(response) is None


@pytest.mark.parametrize("questions", [0, 2])
def test_upstream_requires_exactly_one_question(questions):
    response = bytearray(upstream_response())
    response[4:6] = questions.to_bytes(2)
    assert decode_upstream(bytes(response)) is None


def test_upstream_rejects_every_prefix_truncation_of_an_address_response():
    response = upstream_response(answers=(upstream_record(1, b"1234"),))
    for size in range(len(response)):
        with pytest.raises(DnsFormatError):
            decode_upstream(response[:size])


def test_upstream_checks_records_after_a_usable_address_before_returning():
    response = upstream_response(
        answers=(upstream_record(1, b"1234"),),
        additionals=(upstream_record(16, b"\x03abc"),),
    )
    with pytest.raises(DnsFormatError, match="truncated"):
        decode_upstream(response[:-1])


@pytest.mark.parametrize("kind,data", [(1, b"123"), (1, b"12345"), (28, b"1234")])
def test_upstream_invalid_address_lengths_are_malformed(kind, data):
    with pytest.raises(DnsFormatError, match="address length"):
        decode_upstream(upstream_response(answers=(upstream_record(kind, data),)))


def test_upstream_question_pointer_loop_is_malformed():
    response = (
        struct.pack("!6H", 0x1234, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    )
    with pytest.raises(DnsFormatError, match="pointer loop"):
        decode_upstream(response)


def test_upstream_answer_owner_pointer_loop_is_malformed():
    base = upstream_response()
    offset = len(base)
    owner = (0xC000 | offset).to_bytes(2)
    with pytest.raises(DnsFormatError, match="pointer loop"):
        decode_upstream(
            upstream_response(answers=(upstream_record(1, b"1234", owner=owner),))
        )


@pytest.mark.parametrize("data", [b"", b"\xc0", b"\x00\x00", b"\xc0\xff"])
def test_upstream_cname_rdata_is_validated_even_without_an_address(data):
    with pytest.raises(DnsFormatError):
        decode_upstream(upstream_response(answers=(upstream_record(5, data),)))


def test_upstream_extended_rcode_overrides_an_address():
    opt = upstream_record(41, b"", owner=b"\x00", rrclass=512, ttl=0x01000000)
    response = upstream_response(
        answers=(upstream_record(1, b"1234"),), additionals=(opt,)
    )
    assert decode_upstream(response) is None


def test_upstream_ignores_valid_edns_options_and_unknown_records():
    opt = opt_wire(options=struct.pack("!HH", 65001, 3) + b"abc")
    response = upstream_response(
        answers=(upstream_record(16, b"opaque"), upstream_record(1, b"1234")),
        additionals=(opt,),
    )
    assert decode_upstream(response) == b"1234"
