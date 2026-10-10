import json

import pytest

from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ConfigError
from subio_v2.core.rule_model import (
    BoundRule,
    DefaultParameter,
    LiteralPolicy,
    LogicalExpression,
    ParameterReference,
    ParameterizedRuleSet,
    Predicate,
    RuleComment,
    RuleExpression,
)
from subio_v2.rules.codecs import (
    DEFAULT_RULESET_CODEC_REGISTRY,
    RuleSetInputSelection,
)
from subio_v2.rules.runtime import load_rulesets
from subio_v2.rules.singbox import SINGBOX_SOURCE_SERIALIZER


def _parse(document):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("sing-box", "classical", "source")
    )
    return codec.parse(
        name="singbox_source",
        content=json.dumps(document).encode(),
        context=DialectContext("sing-box", "source"),
    )


@pytest.mark.parametrize("version", range(1, 6))
def test_singbox_source_accepts_official_versions_and_empty_rules(version):
    parsed = _parse({"version": version, "rules": []})

    assert parsed.ruleset.source_context == DialectContext("sing-box", "source")
    assert parsed.ruleset.behavior == "classical"
    assert parsed.ruleset.entries == ()
    assert parsed.issues == ()


@pytest.mark.parametrize(
    "content",
    [
        b"not-json",
        b'{"version":1,"version":2,"rules":[]}',
        b'{"version":1,"rules":[{"domain":"a","domain":"b"}]}',
        b'{"version":NaN,"rules":[]}',
        b"[]",
        b'{"version":1}',
        b'{"version":1,"rules":[],"extra":true}',
    ],
)
def test_singbox_source_rejects_invalid_json_or_root_shape(content):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("sing-box", "classical", "source")
    )

    with pytest.raises(ConfigError):
        codec.parse(
            name="bad",
            content=content,
            context=DialectContext("sing-box", "source"),
        )


@pytest.mark.parametrize("version", [0, 6, True, "1", 1.0, None])
def test_singbox_source_rejects_invalid_versions(version):
    with pytest.raises(ConfigError, match="integer from 1 to 5"):
        _parse({"version": version, "rules": []})


@pytest.mark.parametrize(
    "document",
    [
        {"version": 1, "rules": {}},
        {"version": 1, "rules": ["DOMAIN,example.com"]},
        {"version": 1, "rules": [{"domain": ["ok", 1]}]},
        {"version": 1, "rules": [{"port": True}]},
        {"version": 1, "rules": [{"port": 65536}]},
        {"version": 1, "rules": [{"port_range": "100:99"}]},
        {"version": 1, "rules": [{"ip_cidr": "not-an-ip"}]},
        {"version": 1, "rules": [{"invert": "true"}]},
        {
            "version": 1,
            "rules": [{"type": "logical", "mode": "xor", "rules": []}],
        },
        {
            "version": 1,
            "rules": [{"type": "logical", "mode": "and", "rules": {}}],
        },
    ],
)
def test_singbox_source_validates_rule_shapes_and_matcher_arrays(document):
    with pytest.raises(ConfigError):
        _parse(document)


@pytest.mark.parametrize("mode", [[], {}, 1, True, None])
def test_singbox_source_rejects_non_string_logical_modes_with_config_error(mode):
    with pytest.raises(ConfigError, match=r"\.mode must be 'and' or 'or'"):
        _parse(
            {
                "version": 1,
                "rules": [{"type": "logical", "mode": mode, "rules": [{}]}],
            }
        )


def test_singbox_default_rule_preserves_field_group_boolean_semantics():
    parsed = _parse(
        {
            "version": 5,
            "rules": [
                {
                    "domain": ["exact.example", "other.example"],
                    "domain_suffix": "suffix.example",
                    "ip_cidr": ["192.0.2.1", "2001:db8::/32"],
                    "port": [80, 443],
                    "port_range": "8000:9000",
                    "source_port_range": [":1023", "60000:"],
                    "network": ["tcp", "udp"],
                    "source_ip_cidr": "198.51.100.7",
                    "process_name": ["curl", "wget"],
                    "process_path": "/usr/bin/curl",
                    "process_path_regex": "^/opt/.+",
                }
            ],
        }
    )

    expression = parsed.ruleset.entries[0]
    assert isinstance(expression, LogicalExpression)
    assert expression.operator == "AND"
    assert len(expression.operands) == 8

    destination = expression.operands[0]
    assert isinstance(destination, LogicalExpression)
    assert destination.operator == "OR"
    assert [(item.rule_type, item.matcher) for item in destination.operands] == [
        ("DOMAIN", "exact.example"),
        ("DOMAIN", "other.example"),
        ("DOMAIN-SUFFIX", "suffix.example"),
        ("IP-CIDR", "192.0.2.1/32"),
        ("IP-CIDR6", "2001:db8::/32"),
    ]

    destination_ports = expression.operands[1]
    assert isinstance(destination_ports, LogicalExpression)
    assert [(item.rule_type, item.matcher) for item in destination_ports.operands] == [
        ("DST-PORT", "80"),
        ("DST-PORT", "443"),
        ("DST-PORT", "8000-9000"),
    ]

    source_ports = expression.operands[2]
    assert isinstance(source_ports, LogicalExpression)
    assert [item.matcher for item in source_ports.operands] == [
        "0-1023",
        "60000-65535",
    ]
    assert parsed.issues == ()


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        ({"domain": "one.example", "port": 80, "network": "tcp"}, True),
        ({"domain": "two.example", "port": 443, "network": "udp"}, True),
        ({"domain": "one.example", "port": 81, "network": "tcp"}, False),
        ({"domain": "none.example", "port": 80, "network": "tcp"}, False),
        ({"domain": "one.example", "port": 80, "network": "icmp"}, False),
    ],
)
def test_singbox_array_or_and_field_group_and_truth_table(facts, expected):
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {
                    "domain": ["one.example", "two.example"],
                    "port": [80, 443],
                    "network": ["tcp", "udp"],
                }
            ],
        }
    )

    assert _matches(parsed.ruleset.entries[0], facts) is expected


def test_singbox_logical_rules_and_invert_preserve_exact_tree_semantics():
    parsed = _parse(
        {
            "version": 5,
            "rules": [
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"domain": "direct.example"},
                        {
                            "type": "logical",
                            "mode": "and",
                            "rules": [
                                {"network": "tcp"},
                                {"port": 443},
                            ],
                            "invert": True,
                        },
                    ],
                    "invert": True,
                }
            ],
        }
    )

    expression = parsed.ruleset.entries[0]
    assert isinstance(expression, LogicalExpression)
    assert expression.operator == "NOT"
    outer_or = expression.operands[0]
    assert isinstance(outer_or, LogicalExpression)
    assert outer_or.operator == "OR"
    nested_not = outer_or.operands[1]
    assert isinstance(nested_not, LogicalExpression)
    assert nested_not.operator == "NOT"
    assert isinstance(nested_not.operands[0], LogicalExpression)
    assert nested_not.operands[0].operator == "AND"


@pytest.mark.parametrize(
    ("rule", "field"),
    [
        (
            {"unknown_matcher": "value", "domain": "would-broaden.example"},
            "unknown_matcher",
        ),
        ({"query_type": "A", "domain": "would-broaden.example"}, "query_type"),
        ({"network": ["tcp", "icmp"]}, "network"),
        ({"wifi_ssid": "Home", "domain": "would-broaden.example"}, "wifi_ssid"),
    ],
)
def test_singbox_unsupported_conjunct_rejects_whole_rule(rule, field):
    parsed = _parse(
        {
            "version": 5,
            "rules": [rule, {"domain": "kept.example"}],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert len(parsed.issues) == 1
    assert parsed.issues[0].code == "ruleset.unsupported-source-rule"
    assert parsed.issues[0].field == f"rule 1.{field}"
    assert parsed.issues[0].stage == "parse"


def test_singbox_unsupported_nested_conjunct_rejects_containing_rule_atomically():
    parsed = _parse(
        {
            "version": 5,
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"domain": "must-not-survive.example"},
                        {"future_matcher": "unsupported"},
                    ],
                },
                {"domain_suffix": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN-SUFFIX", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == [
        "rule 1.rules[2].future_matcher"
    ]


@pytest.mark.parametrize(
    ("rule", "field"),
    [
        ({}, "rule 1"),
        ({"invert": True}, "rule 1"),
        ({"domain": []}, "rule 1.domain"),
        ({"domain": "kept.example", "port": []}, "rule 1.port"),
        ({"network": []}, "rule 1.network"),
        (
            {"type": "logical", "mode": "and", "rules": []},
            "rule 1.rules",
        ),
        (
            {"type": "logical", "mode": "or", "rules": []},
            "rule 1.rules",
        ),
    ],
)
def test_singbox_empty_conditions_reject_complete_rule(rule, field):
    parsed = _parse(
        {
            "version": 1,
            "rules": [rule, {"domain": "kept.example"}],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == [field]


def test_singbox_empty_nested_rule_rejects_containing_rule_atomically():
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [{"domain": "must-not-survive.example"}, {}],
                },
                {"domain": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == ["rule 1.rules[2]"]


def test_singbox_known_unsupported_field_selection_is_deterministic():
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {
                    "domain": "must-not-survive.example",
                    "wifi_ssid": "Home",
                    "query_type": "A",
                }
            ],
        }
    )

    assert parsed.ruleset.entries == ()
    assert [issue.field for issue in parsed.issues] == ["rule 1.query_type"]


@pytest.mark.parametrize(
    "pattern",
    [
        r"^(foo|bar)[0-9]+\.example$",
        r"^/opt/[a-z_-]+/bin$",
        r"colou?r",
        r"a{2}",
        r"a{1,2}",
        r"a{1,1000}",
        r"(a{2}){500}",
        r"(a{2}){500,}",
        r"((ab){4}){250}",
        r"([A-Za-z]{2}){500}",
        r"(ordinary|groups)+",
        r"[a:]",
        r"(a\{0002\}){600}",
        r"\{٢\}",
        r"(a\{٢\}){600}",
        r"\{literal\}",
    ],
)
def test_singbox_accepts_conservative_go_re2_regex_subset(pattern):
    parsed = _parse(
        {
            "version": 1,
            "rules": [{"domain_regex": pattern, "process_path_regex": pattern}],
        }
    )

    assert len(parsed.ruleset.entries) == 1
    assert parsed.issues == ()


@pytest.mark.parametrize(
    "pattern",
    [
        "[",
        r"(?=foo)foo",
        r"(?:foo)",
        r"(foo)\1",
        r"foo\Z",
        r"a++",
        r"a{1,2}+",
        r"a{1001}",
        r"(a{2}){600}",
        r"(a{2}){600,}",
        r"((a{5}){10}){21}",
        r"(a{0002}){600}",
        r"(a{1,02}){600}",
        "a{٢}",
        "a{１}",
        "(a{٢}){600}",
        "(a{１}){600}",
        r"([[:alpha:]{2}]){600}",
        r"a{,3}",
        r"word\b",
        r"word\B",
        r"a\u0062",
    ],
)
@pytest.mark.parametrize("field", ["domain_regex", "process_path_regex"])
def test_singbox_rejects_regex_outside_supported_go_re2_subset(field, pattern):
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {field: pattern},
                {"domain": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == [f"rule 1.{field}"]


def test_singbox_deep_regex_grouping_is_a_stable_unsupported_issue():
    pattern = "(" * 500 + "a" + ")" * 500

    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {"domain_regex": pattern},
                {"domain": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert len(parsed.issues) == 1
    assert parsed.issues[0].code == "ruleset.unsupported-source-rule"
    assert parsed.issues[0].field == "rule 1.domain_regex"


@pytest.mark.parametrize(
    ("field", "pattern"),
    [
        ("domain_regex", r"(a{0002}){600}"),
        ("process_path_regex", r"([[:alpha:]{2}]){600}"),
        ("domain_regex", "(a{٢}){600}"),
        ("process_path_regex", "(a{１}){600}"),
    ],
)
def test_singbox_ambiguous_nested_regex_rejects_parent_atomically(field, pattern):
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"domain": "must-not-survive.example"},
                        {field: pattern},
                    ],
                },
                {"domain": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == [f"rule 1.rules[2].{field}"]
    assert "supported Go RE2-compatible subset" in parsed.issues[0].message


def test_singbox_invalid_nested_regex_rejects_containing_rule_atomically():
    parsed = _parse(
        {
            "version": 1,
            "rules": [
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"domain": "must-not-survive.example"},
                        {"domain_regex": [r"valid\.example", r"(bad)\1"]},
                    ],
                },
                {"domain": "kept.example"},
            ],
        }
    )

    assert parsed.ruleset.entries == (
        Predicate("DOMAIN", "kept.example", source_line=2),
    )
    assert [issue.field for issue in parsed.issues] == [
        "rule 1.rules[2].domain_regex[2]"
    ]


@pytest.mark.parametrize(
    ("suffix", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", True),
        ("example.com", "notexample.com", False),
        (".example.com", "example.com", False),
        (".example.com", "www.example.com", True),
        (".example.com", "notexample.com", False),
    ],
)
def test_singbox_domain_suffix_leading_dot_truth_table(suffix, domain, expected):
    parsed = _parse({"version": 1, "rules": [{"domain_suffix": suffix}]})

    assert _matches(parsed.ruleset.entries[0], {"domain": domain}) is expected


@pytest.mark.parametrize("suffix", [".", "..example.com"])
def test_singbox_rejects_ambiguous_leading_dot_suffixes(suffix):
    parsed = _parse({"version": 1, "rules": [{"domain_suffix": suffix}]})

    assert parsed.ruleset.entries == ()
    assert [issue.field for issue in parsed.issues] == ["rule 1.domain_suffix"]


def test_singbox_source_rule_ordinal_reaches_nested_render_issue(monkeypatch):
    content = json.dumps(
        {
            "version": 1,
            "rules": [
                {"domain": "first.example"},
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"domain": "second.example"},
                        {"process_path_regex": r"^/opt/.+"},
                    ],
                },
            ],
        }
    ).encode()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )
    store = load_rulesets(
        [
            {
                "name": "native",
                "url": "https://example.test/source.json",
                "type": "sing-box",
                "behavior": "classical",
                "format": "source",
            }
        ]
    )

    ruleset = store.get("remote_native")
    assert ruleset is not None
    expression = ruleset.model.entries[1].expression
    assert expression.source_line == 2
    assert isinstance(expression, LogicalExpression)
    assert all(operand.source_line == 2 for operand in expression.operands)
    result = ruleset.render_result("surge", "Proxy")
    assert [issue.field for issue in result.issues] == ["line 2"]


def test_singbox_remote_ruleset_uses_existing_loader_and_parameterization(monkeypatch):
    content = json.dumps(
        {"version": 5, "rules": [{"domain_suffix": "example.com"}]}
    ).encode()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    store = load_rulesets(
        [
            {
                "name": "native",
                "url": "https://example.test/source.json",
                "type": "sing-box",
                "behavior": "classical",
                "format": "source",
            }
        ]
    )

    ruleset = store.get("remote_native")
    assert ruleset is not None
    assert ruleset.model.source_context == DialectContext("sing-box", "source")
    assert ruleset.render("mihomo", "Proxy") == ("- DOMAIN-SUFFIX,example.com,Proxy")


def test_singbox_source_serializer_preserves_rules_and_strips_policy_bindings():
    model = ParameterizedRuleSet(
        name="local_rules",
        parameters=("default", "api"),
        entries=(
            RuleComment("# omitted"),
            BoundRule(Predicate("DOMAIN", "one.example"), DefaultParameter()),
            BoundRule(
                Predicate("DOMAIN-SUFFIX", "two.example"),
                ParameterReference("api"),
            ),
            BoundRule(
                LogicalExpression(
                    "AND",
                    (
                        Predicate("NETWORK", "tcp"),
                        LogicalExpression("NOT", (Predicate("DST-PORT", "443"),)),
                    ),
                ),
                LiteralPolicy("PRIVATE-POLICY"),
            ),
        ),
        source_context=DialectContext("mihomo", "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)
    document = json.loads(rendered.content)

    assert document == {
        "version": 1,
        "rules": [
            {"domain": "one.example"},
            {"domain_suffix": "two.example"},
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"network": "tcp"},
                    {"port": 443, "invert": True},
                ],
            },
        ],
    }
    assert rendered.input_rules == 3
    assert rendered.emitted_rules == 3
    assert rendered.issues == ()
    assert "default" not in rendered.content
    assert "api" not in rendered.content
    assert "PRIVATE-POLICY" not in rendered.content


def test_singbox_source_serializer_omits_unsupported_nested_rule_atomically():
    model = ParameterizedRuleSet(
        name="local_rules",
        parameters=("rule",),
        entries=(
            BoundRule(
                LogicalExpression(
                    "OR",
                    (
                        Predicate("DOMAIN", "must-not-survive.example"),
                        Predicate("DOMAIN-WILDCARD", "*.unsupported.example"),
                    ),
                    source_line=2,
                ),
                DefaultParameter(),
            ),
            BoundRule(
                Predicate("DOMAIN", "kept.example", source_line=3),
                DefaultParameter(),
            ),
        ),
        source_context=DialectContext("mihomo", "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [{"domain": "kept.example"}]
    assert rendered.input_rules == 2
    assert rendered.emitted_rules == 1
    assert [issue.code for issue in rendered.issues] == [
        "ruleset.unsupported-target-rule"
    ]
    assert rendered.issues[0].field == "line 2"


def test_singbox_source_serializer_recovers_leading_dot_suffix_and_port_ranges():
    model = ParameterizedRuleSet(
        name="source_rules",
        parameters=("rule",),
        entries=(
            BoundRule(
                LogicalExpression(
                    "AND",
                    (
                        Predicate("DOMAIN-SUFFIX", "example.com"),
                        LogicalExpression("NOT", (Predicate("DOMAIN", "example.com"),)),
                    ),
                ),
                DefaultParameter(),
            ),
            BoundRule(
                Predicate("DST-PORT", "0-1023,60000-65535"),
                DefaultParameter(),
            ),
        ),
        source_context=DialectContext("sing-box", "source"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [
        {"domain_suffix": ".example.com"},
        {
            "type": "logical",
            "mode": "or",
            "rules": [
                {"port_range": ":1023"},
                {"port_range": "60000:"},
            ],
        },
    ]


@pytest.mark.parametrize(
    ("dialect", "protocol"),
    [("surge", "TCP"), ("stash", "uDp")],
)
def test_singbox_source_serializer_canonicalizes_process_paths_and_protocols(
    dialect, protocol
):
    model = ParameterizedRuleSet(
        name="source_rules",
        parameters=("rule",),
        entries=(
            BoundRule(
                Predicate("PROCESS-NAME", "/usr/bin/ssh"), DefaultParameter()
            ),
            BoundRule(Predicate("PROCESS-NAME", "Safari"), DefaultParameter()),
            BoundRule(Predicate("PROTOCOL", protocol), DefaultParameter()),
        ),
        source_context=DialectContext(dialect, "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [
        {"process_path": "/usr/bin/ssh"},
        {"process_name": "Safari"},
        {"network": protocol.lower()},
    ]
    assert rendered.emitted_rules == 3
    assert rendered.issues == ()


@pytest.mark.parametrize("dialect", ["surge", "stash"])
def test_singbox_source_serializer_rejects_non_equivalent_process_and_protocol_forms(
    dialect,
):
    model = ParameterizedRuleSet(
        name="source_rules",
        parameters=("rule",),
        entries=(
            BoundRule(Predicate("PROCESS-NAME", "Chrome*"), DefaultParameter()),
            BoundRule(
                Predicate("PROCESS-NAME", "/Applications/ChatGPT.app/"),
                DefaultParameter(),
            ),
            BoundRule(Predicate("PROTOCOL", "http"), DefaultParameter()),
            BoundRule(Predicate("DOMAIN", "kept.example"), DefaultParameter()),
        ),
        source_context=DialectContext(dialect, "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [{"domain": "kept.example"}]
    assert rendered.input_rules == 4
    assert rendered.emitted_rules == 1
    assert [issue.code for issue in rendered.issues] == [
        "ruleset.unsupported-target-rule",
        "ruleset.unsupported-target-rule",
        "ruleset.unsupported-target-rule",
    ]
    assert "Chrome*" not in rendered.content
    assert "ChatGPT.app" not in rendered.content
    assert "http" not in rendered.content


def test_singbox_source_serializer_maps_mihomo_src_without_stripping_co_options():
    model = ParameterizedRuleSet(
        name="source_rules",
        parameters=("rule",),
        entries=(
            BoundRule(
                Predicate("IP-CIDR", "192.0.2.0/24", ("src",)),
                DefaultParameter(),
            ),
            BoundRule(
                Predicate("IP-CIDR6", "2001:db8::/32", ("src",)),
                DefaultParameter(),
            ),
            BoundRule(
                Predicate(
                    "IP-CIDR", "198.51.100.0/24", ("src", "no-resolve")
                ),
                DefaultParameter(),
            ),
            BoundRule(Predicate("DOMAIN", "kept.example"), DefaultParameter()),
        ),
        source_context=DialectContext("mihomo", "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [
        {"source_ip_cidr": "192.0.2.0/24"},
        {"source_ip_cidr": "2001:db8::/32"},
        {"domain": "kept.example"},
    ]
    assert rendered.input_rules == 4
    assert rendered.emitted_rules == 3
    assert [issue.code for issue in rendered.issues] == [
        "ruleset.unsupported-target-option"
    ]
    assert "198.51.100.0/24" not in rendered.content


def test_singbox_source_serializer_rejects_nested_unsupported_option_atomically():
    model = ParameterizedRuleSet(
        name="source_rules",
        parameters=("rule",),
        entries=(
            BoundRule(
                LogicalExpression(
                    "AND",
                    (
                        Predicate("DOMAIN", "must-not-survive.example"),
                        Predicate(
                            "IP-CIDR",
                            "192.0.2.0/24",
                            ("src", "no-resolve"),
                        ),
                    ),
                    source_line=2,
                ),
                DefaultParameter(),
            ),
            BoundRule(
                Predicate("DOMAIN", "kept.example", source_line=3),
                DefaultParameter(),
            ),
        ),
        source_context=DialectContext("mihomo", "text"),
    )

    rendered = SINGBOX_SOURCE_SERIALIZER.render(model)

    assert json.loads(rendered.content)["rules"] == [{"domain": "kept.example"}]
    assert rendered.input_rules == 2
    assert rendered.emitted_rules == 1
    assert [issue.code for issue in rendered.issues] == [
        "ruleset.unsupported-target-option"
    ]
    assert rendered.issues[0].field == "line 2"


def _matches(expression: RuleExpression, facts: dict[str, object]) -> bool:
    if isinstance(expression, LogicalExpression):
        values = [_matches(operand, facts) for operand in expression.operands]
        if expression.operator == "AND":
            return all(values)
        if expression.operator == "OR":
            return any(values)
        if expression.operator == "NOT":
            return not values[0]
        raise AssertionError(expression.operator)
    if expression.rule_type == "MATCH":
        return True
    if expression.rule_type == "DOMAIN":
        return facts.get("domain") == expression.matcher
    if expression.rule_type == "DOMAIN-SUFFIX":
        domain = facts.get("domain")
        return isinstance(domain, str) and (
            domain == expression.matcher or domain.endswith(f".{expression.matcher}")
        )
    if expression.rule_type == "DST-PORT":
        return facts.get("port") == int(expression.matcher)
    if expression.rule_type == "NETWORK":
        return facts.get("network") == expression.matcher
    raise AssertionError(expression.rule_type)
