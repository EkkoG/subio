import pytest

from subio_v2.surge.syntax import (
    SurgeParameter,
    SurgeParameters,
    SurgeProxyRecord,
    parse_parameter_list,
    parse_proxy_line,
    serialize_parameter_list,
    serialize_proxy_line,
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
