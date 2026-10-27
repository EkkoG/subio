import pytest

from subio_v2.adapters.catalog import get_parser
from subio_v2.adapters.surge.syntax import (
    SurgeParameter,
    SurgeParameters,
    SurgeProxyRecord,
    parse_parameter_list,
    parse_proxy_line,
    serialize_comma_separated,
    serialize_parameter_list,
    serialize_proxy_line,
    split_comma_separated,
)


def test_parse_preserves_order_duplicates_and_last_value_lookup():
    record = parse_proxy_line(
        "Example = vmess, host.example.com, 443, tag = first, "
        'ws-headers="Host:cdn.example.com,X-Trace:a=b", tag=second'
    )

    assert record.name == "Example"
    assert record.type == "vmess"
    assert record.positional == ("host.example.com", "443")
    assert record.parameters.items() == (
        ("tag", "first"),
        ("ws-headers", "Host:cdn.example.com,X-Trace:a=b"),
        ("tag", "second"),
    )
    assert record.parameters.get("tag") == "second"
    assert record.parameters.get_all("tag") == ("first", "second")
    assert record.parameters.get("missing") is None
    assert record.parameters.get("missing", "fallback") == "fallback"


def test_parse_supports_quoted_commas_whitespace_and_value_equals():
    record = parse_proxy_line(
        "  Spaced Name  =  http  ,  proxy.example.com  ,  8080  , "
        'note = "  keep, this = value  " , expression=a=b=c  '
    )

    assert record.name == "Spaced Name"
    assert record.type == "http"
    assert record.positional == ("proxy.example.com", "8080")
    assert record.parameters.get("note") == "  keep, this = value  "
    assert record.parameters.get("expression") == "a=b=c"


def test_serialize_quotes_only_when_required_and_round_trips():
    record = SurgeProxyRecord(
        name="Example",
        type="custom",
        positional=("host.example.com", "a=b", " padded ", ""),
        parameters=SurgeParameters(
            (
                SurgeParameter("plain", "a=b"),
                SurgeParameter("list", "h3,h2"),
                SurgeParameter("quoted", 'say "hello"'),
                SurgeParameter("tag", "one"),
                SurgeParameter("tag", "two"),
            )
        ),
    )

    line = serialize_proxy_line(record)

    assert line == (
        'Example = custom, host.example.com, "a=b", " padded ", "", '
        'plain=a=b, list="h3,h2", quoted="say \\"hello\\"", tag=one, tag=two'
    )
    assert parse_proxy_line(line) == record


def test_parameters_are_an_ordered_sequence():
    parameters = SurgeParameters((SurgeParameter("a", "1"), SurgeParameter("a", "2")))

    assert len(parameters) == 2
    assert parameters[0] == SurgeParameter("a", "1")
    assert list(parameters) == [
        SurgeParameter("a", "1"),
        SurgeParameter("a", "2"),
    ]
    assert parameters.last_values == {"a": "2"}


def test_parameter_list_supports_quoted_commas_and_repeated_keys():
    parameters = parse_parameter_list('type = p12, password = "a,b", tag=one, tag=two')

    assert parameters.items() == (
        ("type", "p12"),
        ("password", "a,b"),
        ("tag", "one"),
        ("tag", "two"),
    )
    assert serialize_parameter_list(parameters, spaced_equals=True) == (
        'type = p12, password = "a,b", tag = one, tag = two'
    )


def test_split_list_keeps_parenthesized_wireguard_peers_intact():
    peers = split_comma_separated(
        '(public-key = a, allowed-ips = "0.0.0.0/0, ::/0", endpoint = a:1), '
        "(public-key = b, allowed-ips = 10.0.0.0/8, endpoint = b:2)"
    )

    assert len(peers) == 2
    assert peers[0].startswith("(public-key = a")
    assert peers[1].endswith("endpoint = b:2)")


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("missing separator", "must contain '='"),
        (" = http, host, 80", "name is required"),
        ("name = ", "type is required"),
        ('name = http, "unterminated', "unterminated double quote"),
        ("name = http, host, 80, =value", "parameter key is required"),
    ],
)
def test_invalid_lines_raise_value_error(line, message):
    with pytest.raises(ValueError, match=message):
        parse_proxy_line(line)


def test_serializer_rejects_invalid_record_identity():
    with pytest.raises(ValueError, match="name cannot contain"):
        serialize_proxy_line(
            SurgeProxyRecord(name="bad=name", type="http", positional=())
        )


@pytest.mark.parametrize("name", [
    "#hidden", "//hidden", " #hidden", " //hidden", " ", "  ",
    " leading", "trailing ", " both ",
])
def test_serializer_rejects_names_that_would_be_comments_or_trimmed(name):
    with pytest.raises(ValueError, match="Surge proxy name"):
        serialize_proxy_line(SurgeProxyRecord(name=name, type="direct"))


@pytest.mark.parametrize("name", ["plain", "foo#bar", "foo//bar", "internal space"])
def test_serializer_preserves_names_with_internal_comment_markers_or_spaces(name):
    record = SurgeProxyRecord(name=name, type="direct")
    assert parse_proxy_line(serialize_proxy_line(record)) == record


@pytest.mark.parametrize("value", [
    "(", ")", "left(", "right)", "balanced(value)", "comma,value",
    'say "hello"', " padded ", r"back\slash", r'quoted\"slash', "literal=value",
])
def test_literal_atoms_and_csv_elements_keep_parentheses_and_other_delimiters(value):
    record = SurgeProxyRecord(
        name="literal", type="custom", positional=(value,),
        parameters=SurgeParameters((SurgeParameter("value", value),)),
    )
    assert parse_proxy_line(serialize_proxy_line(record)) == record
    values = [value, "neighbor", ""]
    assert split_comma_separated(serialize_comma_separated(values)) == tuple(values)


def test_quoted_literal_parentheses_do_not_replace_structural_peer_parentheses():
    peer = serialize_parameter_list([
        SurgeParameter("public-key", "left("),
        SurgeParameter("endpoint", "right):51820"),
    ], spaced_equals=True)
    record = "(" + peer + ")"
    peers = split_comma_separated(record + ", " + record)
    assert peers == (record, record)
    assert parse_parameter_list(peers[0][1:-1]).last_values == {
        "public-key": "left(", "endpoint": "right):51820",
    }


@pytest.mark.parametrize("name", ["plain", "[literal]", "[open"])
@pytest.mark.parametrize("value", ["pw]", "safe", "pw]x", "pw],", 'quoted"pw]'])
@pytest.mark.parametrize("placement", ["positional", "parameter"])
def test_proxy_line_does_not_become_a_document_section(name, value, placement):
    record = SurgeProxyRecord(
        name=name,
        type="socks5",
        positional=("example.test", "1080", "user", value) if placement == "positional" else ("example.test", "1080"),
        parameters=SurgeParameters([SurgeParameter("password", value)]) if placement == "parameter" else SurgeParameters(),
    )
    line = serialize_proxy_line(record)
    assert parse_proxy_line(line) == record
    for prefix in ("", "[Proxy]\n"):
        parsed = get_parser("surge").parse_result(prefix + line + "\nhealthy = socks5, healthy.test, 1080")
        assert not parsed.issues
        assert [node.name for node in parsed.nodes] == [name, "healthy"]
        assert parsed.nodes[0].password == value
        assert parsed.nodes[1].server == "healthy.test"
