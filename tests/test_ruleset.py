from pathlib import Path

import pytest

from subio_v2.dialect import DialectContext
from subio_v2.errors import ConfigError
from subio_v2.model.rules import (
    BoundRule,
    DefaultParameter,
    LiteralPolicy,
    ParameterizedRuleSet,
    ParameterReference,
    Predicate,
    RuleComment,
)
from subio_v2.rules.codecs import (
    DEFAULT_RULESET_CODEC_REGISTRY,
    RuleSetInputSelection,
)
from subio_v2.rules.parser import (
    MIHOMO_CLASSICAL_PARSER,
    MIHOMO_CLASSICAL_SPEC,
    STASH_CLASSICAL_SPEC,
    SURGE_CLASSICAL_SPEC,
    split_rule_tokens,
)
from subio_v2.rules.runtime import (
    RuleIssueCollector,
    RuleSet,
    RuleSetStore,
    load_rulesets,
    load_snippets,
    merge_stores,
)

FIXTURES = Path(__file__).parent / "fixtures/rulesets"

EXPECTED_SELF_CONTAINED_RULES = {
    "mihomo": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-REGEX",
        "GEOSITE",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-SUFFIX",
        "IP-ASN",
        "GEOIP",
        "SRC-GEOIP",
        "SRC-IP-ASN",
        "SRC-IP-CIDR",
        "SRC-IP-SUFFIX",
        "DST-PORT",
        "SRC-PORT",
        "IN-PORT",
        "IN-TYPE",
        "IN-USER",
        "IN-NAME",
        "REMATCH-NAME",
        "PROCESS-PATH",
        "PROCESS-PATH-WILDCARD",
        "PROCESS-PATH-REGEX",
        "PROCESS-NAME",
        "PROCESS-NAME-WILDCARD",
        "PROCESS-NAME-REGEX",
        "UID",
        "NETWORK",
        "DSCP",
        "MATCH",
    },
    "stash": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-REGEX",
        "GEOSITE",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "GEOIP",
        "SRC-IP",
        "DST-PORT",
        "PROCESS-NAME",
        "PROCESS-PATH",
        "USER-AGENT",
        "URL-REGEX",
        "NETWORK",
        "PROTOCOL",
        "MATCH",
    },
    "surge": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "GEOIP",
        "SRC-IP",
        "SRC-PORT",
        "DEST-PORT",
        "IN-PORT",
        "PROCESS-NAME",
        "USER-AGENT",
        "URL-REGEX",
        "PROTOCOL",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "HOSTNAME-TYPE",
        "SUBNET",
        "CELLULAR-RADIO",
        "CELLULAR-CARRIER",
    },
}


def make_ruleset(
    entries,
    *,
    name="test",
    parameters=("rule",),
    issues=(),
    dialect="mihomo",
):
    return RuleSet(
        ParameterizedRuleSet(
            name=name,
            parameters=parameters,
            entries=tuple(entries),
            source_context=DialectContext(dialect, "text"),
            issues=tuple(issues),
        )
    )


def bind(expression, binding=None):
    return BoundRule(expression, binding or DefaultParameter())


def parameterize(parsed):
    return make_ruleset(
        [
            entry if isinstance(entry, RuleComment) else bind(entry)
            for entry in parsed.ruleset.entries
        ],
        name=parsed.ruleset.name,
        issues=parsed.issues,
        dialect=parsed.ruleset.source_context.dialect,
    )


def test_official_predicate_inventories_are_explicit():
    assert set(MIHOMO_CLASSICAL_SPEC.predicates) | set(
        MIHOMO_CLASSICAL_SPEC.catch_all_rules
    ) == EXPECTED_SELF_CONTAINED_RULES["mihomo"]
    assert (
        set(STASH_CLASSICAL_SPEC.predicates)
        - set(STASH_CLASSICAL_SPEC.external_dependency_rules)
    ) | set(STASH_CLASSICAL_SPEC.catch_all_rules) == EXPECTED_SELF_CONTAINED_RULES[
        "stash"
    ]
    assert (
        set(SURGE_CLASSICAL_SPEC.predicates)
        - set(SURGE_CLASSICAL_SPEC.external_dependency_rules)
    ) == EXPECTED_SELF_CONTAINED_RULES["surge"]
    assert STASH_CLASSICAL_SPEC.global_options == {"no-track"}
    assert "extended-matching" in SURGE_CLASSICAL_SPEC.allowed_options["URL-REGEX"]


@pytest.mark.parametrize(
    ("dialect", "platform", "rule_type"),
    [
        (dialect, dialect, rule_type)
        for dialect, rule_types in EXPECTED_SELF_CONTAINED_RULES.items()
        for rule_type in sorted(rule_types)
    ],
)
def test_every_self_contained_predicate_has_same_dialect_lowering(
    dialect, platform, rule_type
):
    matcher = "" if rule_type == "MATCH" else "value"
    if rule_type in {"DST-PORT", "SRC-PORT", "DEST-PORT", "IN-PORT"}:
        matcher = "443"
    ruleset = make_ruleset(
        [bind(Predicate(rule_type, matcher))],
        dialect=dialect,
    )

    result = ruleset.render_result(platform, "Proxy")

    assert result.content
    assert result.issues == ()


@pytest.mark.parametrize(
    ("dialect", "behavior", "format_name"),
    [
        (dialect, behavior, format_name)
        for dialect in ("mihomo", "stash")
        for behavior in ("classical", "domain", "ipcidr")
        for format_name in ("text", "yaml")
    ]
    + [
        (dialect, behavior, "mrs")
        for dialect in ("mihomo", "stash")
        for behavior in ("domain", "ipcidr")
    ]
    + [("surge", "classical", "text"), ("surge", "domain", "text")],
)
def test_registry_parses_every_supported_combination(dialect, behavior, format_name):
    if format_name == "mrs":
        fixture = FIXTURES / "mrs" / f"{behavior}.mrs"
    elif dialect == "surge":
        fixture = FIXTURES / dialect / (
            "rule-set.list" if behavior == "classical" else "domain-set.list"
        )
    else:
        suffix = "yaml" if format_name == "yaml" else "list"
        fixture = FIXTURES / dialect / f"{behavior}-{format_name}.{suffix}"
    selection = RuleSetInputSelection(dialect, behavior, format_name)
    parsed = DEFAULT_RULESET_CODEC_REGISTRY.get(selection).parse(
        name="fixture",
        content=fixture.read_bytes(),
        context=DialectContext(dialect, format_name),
    )

    assert parsed.ruleset.behavior == behavior
    assert parsed.ruleset.entries or parsed.issues


@pytest.mark.parametrize(
    "selection",
    [
        RuleSetInputSelection("surge", "classical", "yaml"),
        RuleSetInputSelection("surge", "ipcidr", "text"),
        RuleSetInputSelection("mihomo", "classical", "mrs"),
        RuleSetInputSelection("stash", "classical", "mrs"),
        RuleSetInputSelection("surge", "domain", "mrs"),
    ],
)
def test_registry_rejects_illegal_combinations(selection):
    with pytest.raises(ConfigError, match="Unsupported ruleset input combination"):
        DEFAULT_RULESET_CODEC_REGISTRY.get(selection)


def test_untyped_remote_is_exactly_mihomo_classical_text(monkeypatch):
    content = (FIXTURES / "mihomo/classical-text.list").read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    store = load_rulesets([{"name": "default", "url": "https://example.test/rules"}])
    ruleset = store.get("remote_default")

    assert ruleset is not None
    assert ruleset.model.source_context == DialectContext("mihomo", "text")
    assert "- IP-CIDR,192.0.2.0/24,Proxy,src,no-resolve" in ruleset.render(
        "mihomo", "Proxy"
    )


def test_untyped_remote_does_not_sniff_mihomo_yaml(monkeypatch):
    content = (FIXTURES / "mihomo/classical-yaml.yaml").read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    with pytest.raises(ConfigError, match="invalid rule type"):
        load_rulesets([{"name": "default", "url": "https://example.test/rules"}])


def test_text_codecs_require_utf8():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("mihomo", "classical", "text")
    )
    parsed = codec.parse(
        name="bom",
        content=b"\xef\xbb\xbfDOMAIN,example.com",
        context=DialectContext("mihomo", "text"),
    )
    assert parsed.ruleset.entries
    with pytest.raises(ConfigError, match="valid UTF-8"):
        codec.parse(
            name="bad",
            content=b"\xff",
            context=DialectContext("mihomo", "text"),
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"rules: []\n",
        b"payload: value\n",
        b"payload:\n  - DOMAIN,example.com\npayload: []\n",
        b"payload:\n  - !!python/object/apply:os.system ['id']\n",
    ],
)
def test_yaml_codec_rejects_noncanonical_or_unsafe_documents(payload):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("mihomo", "classical", "yaml")
    )
    with pytest.raises(ConfigError):
        codec.parse(
            name="bad",
            content=payload,
            context=DialectContext("mihomo", "yaml"),
        )


def test_domain_semantics_are_dialect_specific():
    mihomo_codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("mihomo", "domain", "text")
    )
    surge_codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("surge", "domain", "text")
    )
    mihomo = parameterize(
        mihomo_codec.parse(
            name="mihomo_domain",
            content=b".example.com\n",
            context=DialectContext("mihomo", "text"),
        )
    )
    surge = parameterize(
        surge_codec.parse(
            name="surge_domain",
            content=b".example.com\n",
            context=DialectContext("surge", "text"),
        )
    )

    assert mihomo.render("mihomo", "Proxy") == (
        "- AND,((DOMAIN-SUFFIX,example.com),"
        "(NOT,((DOMAIN,example.com)))),Proxy"
    )
    assert surge.render("surge", "Proxy") == "DOMAIN-SUFFIX,example.com,Proxy"


def test_label_wildcard_lowers_to_exact_regex_or_issue():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("mihomo", "domain", "text")
    )
    ruleset = parameterize(
        codec.parse(
            name="wildcard",
            content=b"*.cdn.example.net\n",
            context=DialectContext("mihomo", "text"),
        )
    )

    assert ruleset.render("mihomo", "Proxy") == (
        r"- DOMAIN-REGEX,^[^.]*\.cdn\.example\.net$,Proxy"
    )
    result = ruleset.render_result("surge", "Proxy")
    assert result.content == ""
    assert [issue.code for issue in result.issues] == [
        "ruleset.unsupported-target-rule"
    ]


def test_tokenizer_preserves_quoted_commas_and_regex_backslashes():
    tokens = split_rule_tokens(
        r'URL-REGEX,"^https://example\.com/a,b$",notification-text="Hit,Now"'
    )
    assert tokens == (
        "URL-REGEX",
        r"^https://example\.com/a,b$",
        'notification-text="Hit,Now"',
    )


def test_surge_quoted_matcher_and_key_value_options_round_trip():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("surge", "classical", "text")
    )
    parsed = codec.parse(
        name="quoted",
        content=(
            r'URL-REGEX,"^https://example\.com/a,b$",'
            'notification-text="Hit,Now"\n'
        ).encode(),
        context=DialectContext("surge", "text"),
    )

    assert parameterize(parsed).render("surge", "Proxy") == (
        r'URL-REGEX,"^https://example\\.com/a,b$",Proxy,'
        'notification-text="Hit,Now"'
    )


def test_surge_url_regex_accepts_extended_matching_inside_rule_set():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("surge", "classical", "text")
    )
    parsed = codec.parse(
        name="extended_url",
        content=b"URL-REGEX,^https://example.com/,extended-matching\n",
        context=DialectContext("surge", "text"),
    )

    assert parameterize(parsed).render("surge", "Proxy") == (
        "URL-REGEX,^https://example.com/,Proxy,extended-matching"
    )


def test_comma_port_matcher_is_not_misread_as_policy():
    parsed = MIHOMO_CLASSICAL_PARSER.parse_headless(
        name="ports",
        lines=[(1, "DST-PORT,80,443")],
        source_context=DialectContext("mihomo", "text"),
    )
    rule = parsed.ruleset.entries[0]
    assert isinstance(rule, Predicate)
    assert rule.matcher == "80,443"
    assert parameterize(parsed).render("mihomo", "Proxy") == (
        "- DST-PORT,80,443,Proxy"
    )


def test_nested_logic_binds_policy_only_to_outer_expression():
    source = (FIXTURES / "snippets/outer_logic").read_text()
    parsed = MIHOMO_CLASSICAL_PARSER.parse_snippet(
        name="outer_logic",
        parameter_names=("rule",),
        content="\n".join(source.splitlines()[1:]),
        source_context=DialectContext("mihomo", "text"),
    )
    ruleset = make_ruleset(parsed.entries, name="outer_logic")

    assert ruleset.render("mihomo", "Proxy") == (
        "- AND,((DOMAIN-SUFFIX,example.org),"
        "(OR,((NETWORK,udp),(NOT,((DST-PORT,443)))))),Proxy"
    )


def test_surge_comments_and_inline_comments_are_normalized():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("surge", "classical", "text")
    )
    parsed = codec.parse(
        name="comments",
        content=b"; heading\nDOMAIN,example.com ; tail\n",
        context=DialectContext("surge", "text"),
    )
    ruleset = parameterize(parsed)

    assert ruleset.render("stash", "Proxy") == (
        "# heading\n- DOMAIN,example.com,Proxy"
    )


def test_external_script_dependency_is_an_issue_not_an_expression():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("stash", "classical", "text")
    )
    parsed = codec.parse(
        name="scripted",
        content=b"DOMAIN,example.com\nSCRIPT,quic\n",
        context=DialectContext("stash", "text"),
    )
    ruleset = parameterize(parsed)
    result = ruleset.render_result("stash", "Proxy")

    assert result.content == "- DOMAIN,example.com,Proxy"
    assert [issue.code for issue in result.issues] == [
        "ruleset.external-script-dependency"
    ]


def test_stash_no_track_is_preserved_only_for_stash_targets():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("stash", "classical", "text")
    )
    parsed = codec.parse(
        name="no_track",
        content=b"DOMAIN,example.com,no-track\n",
        context=DialectContext("stash", "text"),
    )
    ruleset = parameterize(parsed)

    assert ruleset.render("stash", "Proxy") == (
        "- DOMAIN,example.com,Proxy,no-track"
    )
    result = ruleset.render_result("mihomo", "Proxy")
    assert result.content == ""
    assert [issue.code for issue in result.issues] == [
        "ruleset.unsupported-target-option"
    ]


def test_source_ip_rules_lower_between_mihomo_stash_and_surge():
    surge = make_ruleset(
        [bind(Predicate("SRC-IP", "192.0.2.0/24"))],
        dialect="surge",
    )
    assert surge.render("mihomo", "Proxy") == (
        "- SRC-IP-CIDR,192.0.2.0/24,Proxy"
    )

    mihomo = make_ruleset(
        [bind(Predicate("SRC-IP-CIDR", "198.51.100.0/24"))],
        dialect="mihomo",
    )
    assert mihomo.render("surge", "Proxy") == (
        "SRC-IP,198.51.100.0/24,Proxy"
    )
    assert mihomo.render("stash", "Proxy") == (
        "- SRC-IP,198.51.100.0/24,Proxy"
    )

    src_option = make_ruleset(
        [
            bind(
                Predicate(
                    "IP-CIDR",
                    "203.0.113.0/24",
                    ("src", "no-resolve"),
                )
            )
        ],
        dialect="mihomo",
    )
    assert src_option.render("mihomo", "Proxy") == (
        "- IP-CIDR,203.0.113.0/24,Proxy,src,no-resolve"
    )
    assert src_option.render("surge", "Proxy") == (
        "SRC-IP,203.0.113.0/24,Proxy"
    )


def test_process_matcher_semantics_lower_without_same_name_misrendering():
    surge = make_ruleset(
        [
            bind(Predicate("PROCESS-NAME", "Chrome*")),
            bind(Predicate("PROCESS-NAME", "/usr/bin/ssh")),
            bind(Predicate("PROCESS-NAME", "/Applications/ChatGPT.app/")),
        ],
        dialect="surge",
    )

    assert surge.render("mihomo", "Proxy") == (
        "- PROCESS-NAME-WILDCARD,Chrome*,Proxy\n"
        "- PROCESS-PATH,/usr/bin/ssh,Proxy\n"
        "- PROCESS-PATH-WILDCARD,/Applications/ChatGPT.app/*,Proxy"
    )
    clash = surge.render_result("clash", "Proxy")
    assert clash.content == ""
    assert len(clash.issues) == 3
    assert all(
        issue.code == "ruleset.unsupported-target-rule" for issue in clash.issues
    )

    mihomo = make_ruleset(
        [
            bind(Predicate("PROCESS-NAME-WILDCARD", "Telegram*")),
            bind(Predicate("PROCESS-PATH-WILDCARD", "/Applications/*.app/*")),
        ],
        dialect="mihomo",
    )
    assert mihomo.render("surge", "Proxy") == (
        "PROCESS-NAME,Telegram*,Proxy\n"
        "PROCESS-NAME,/Applications/*.app/*,Proxy"
    )


def test_surge_final_and_pre_matching_are_rejected():
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("surge", "classical", "text")
    )
    final = codec.parse(
        name="final",
        content=b"FINAL\n",
        context=DialectContext("surge", "text"),
    )
    assert [issue.code for issue in final.issues] == ["ruleset.non-shareable-rule"]

    with pytest.raises(ConfigError, match="pre-matching"):
        codec.parse(
            name="pre",
            content=b"DOMAIN-SUFFIX,example.com,pre-matching\n",
            context=DialectContext("surge", "text"),
        )


def test_renderer_reports_unsupported_rules_instead_of_silently_deleting():
    ruleset = make_ruleset([bind(Predicate("USER-AGENT", "*Safari*", source_line=7))])
    result = ruleset.render_result("mihomo", "Proxy")

    assert result.content == ""
    assert len(result.issues) == 1
    assert result.issues[0].code == "ruleset.unsupported-target-rule"
    assert result.issues[0].field == "line 7"


def test_mihomo_alias_uses_canonical_lowering_and_issue_targets():
    ruleset = make_ruleset(
        [
            bind(Predicate("SRC-IP", "192.0.2.1")),
            bind(Predicate("PROTOCOL", "tcp")),
            bind(Predicate("IP-CIDR", "198.51.100.0/24", ("src",))),
            bind(Predicate("USER-AGENT", "*Safari*", source_line=9)),
        ]
    )

    canonical = ruleset.render_result("mihomo", "Proxy")
    alias = ruleset.render_result("clash-meta", "Proxy")

    assert canonical.content == (
        "- SRC-IP-CIDR,192.0.2.1/32,Proxy\n"
        "- NETWORK,tcp,Proxy\n"
        "- IP-CIDR,198.51.100.0/24,Proxy,src"
    )
    assert alias == canonical
    assert [issue.target for issue in alias.issues] == ["mihomo"]


def test_renderer_rejects_unknown_target_instead_of_failing_open():
    ruleset = make_ruleset([bind(Predicate("USER-AGENT", "*Safari*"))])

    with pytest.raises(ValueError, match="Unknown ruleset target platform"):
        ruleset.render("unknown", "Proxy")


def test_rule_renderer_preserves_existing_target_forms():
    ruleset = make_ruleset(
        [
            RuleComment("# comment"),
            bind(Predicate("DOMAIN", "example.com")),
            bind(Predicate("DST-PORT", "443"), LiteralPolicy("Direct")),
            bind(Predicate("MATCH")),
        ]
    )

    assert ruleset.render("surge", "Proxy") == (
        "# comment\nDOMAIN,example.com,Proxy\nDEST-PORT,443,Direct\nFINAL,Proxy"
    )
    assert ruleset.render("mihomo", "Proxy") == (
        "# comment\n- DOMAIN,example.com,Proxy\n"
        "- DST-PORT,443,Direct\n- MATCH,Proxy"
    )


def test_callable_binding_and_collector_are_explicit():
    ruleset = make_ruleset(
        [
            bind(Predicate("DOMAIN", "default.example")),
            bind(Predicate("DOMAIN", "api.example"), ParameterReference("api")),
        ],
        parameters=("default", "api"),
    )
    collector = RuleIssueCollector()
    callable_rule = ruleset.as_callable("mihomo", collector)

    assert callable_rule("Default", api="Api") == (
        "- DOMAIN,default.example,Default\n- DOMAIN,api.example,Api"
    )
    assert collector.issues == []
    with pytest.raises(TypeError, match="missing required argument"):
        callable_rule("Default")
    with pytest.raises(TypeError, match="unexpected argument"):
        callable_rule("Default", api="Api", extra="x")


def test_ruleset_store_and_merge_keep_callable_names():
    first = RuleSetStore()
    second = RuleSetStore()
    first.register("first", make_ruleset([], name="first"))
    second.register("second", make_ruleset([], name="second"))

    merged = merge_stores(first, second)
    assert merged.names == ["first", "second"]
    assert set(merged.get_callables("surge")) == {"first", "second"}


def test_load_snippets_supports_default_named_and_literal_bindings(tmp_path):
    for name in ("default_rule", "named_rules", "literal_policy"):
        (tmp_path / name).write_text((FIXTURES / "snippets" / name).read_text())

    store = load_snippets(str(tmp_path))

    assert "default.example,Default" in store.get("default_rule").render(
        "surge", "Default"
    )
    assert "api.example,Api" in store.get("named_rules").render(
        "surge", "Default", api_rule="Api"
    )
    assert store.get("literal_policy").render("surge", "Proxy") == (
        "DOMAIN,internal.example,DIRECT"
    )


@pytest.mark.parametrize(
    "fixture_name",
    ["arbitrary_invalid_text", "undeclared_reference"],
)
def test_invalid_snippets_fail_closed(tmp_path, fixture_name):
    (tmp_path / fixture_name).write_text(
        (FIXTURES / "snippets" / fixture_name).read_text()
    )
    with pytest.raises(ConfigError):
        load_snippets(str(tmp_path))
