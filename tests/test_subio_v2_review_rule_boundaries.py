import pytest
import yaml

from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ConfigError
from subio_v2.core.rule_model import (
    BoundRule, DefaultParameter, LogicalExpression, ParameterizedRuleSet,
    Predicate, RuleComment,
)
from subio_v2.rules.codecs import DEFAULT_RULESET_CODEC_REGISTRY, RuleSetInputSelection
from subio_v2.rules.parser import (
    MIHOMO_CLASSICAL_PARSER, STASH_CLASSICAL_PARSER, SURGE_CLASSICAL_PARSER,
)
from subio_v2.rules.runtime import RuleSet
from tests.test_ruleset import parameterize


def snippet(content, parameters=("rule",), parser=MIHOMO_CLASSICAL_PARSER):
    parsed = parser.parse_snippet(
        name="test", parameter_names=parameters, content=content,
        source_context=DialectContext(parser.spec.dialect, "text"),
    )
    return RuleSet(ParameterizedRuleSet(
        name="test", parameters=parameters, entries=parsed.entries,
        source_context=DialectContext(parser.spec.dialect, "text"),
    ))


def nested_rule(depth):
    value = "DOMAIN,example.test"
    for _ in range(depth):
        value = f"NOT,(({value}))"
    return value


@pytest.mark.parametrize("behavior", ["classical", "domain", "ipcidr"])
def test_complex_yaml_keys_use_the_config_error_boundary(behavior):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(
        RuleSetInputSelection("mihomo", behavior, "yaml")
    )
    with pytest.raises(ConfigError, match="not valid YAML"):
        codec.parse(name="test", content=b"payload: []\n? [bad]\n: ignored\n",
                    context=DialectContext("mihomo", "yaml"))


@pytest.mark.parametrize("name", ["platform", "self", "values", "kwargs"])
def test_snippet_parameter_names_do_not_collide_with_python_arguments(name):
    rules = snippet("DOMAIN,example.test", (name,))
    assert rules.as_callable("mihomo")(**{name: "DIRECT"}) == "- DOMAIN,example.test,DIRECT"
    assert rules.render("mihomo", **{name: "DIRECT"}) == "- DOMAIN,example.test,DIRECT"


def test_quoted_numeric_policy_survives_port_round_trip():
    rules = snippet('DST-PORT,80,"443"')
    assert rules.model.entries[0].expression.matcher == "80"
    rendered = rules.render("mihomo", "Proxy")
    reparsed = snippet(yaml.safe_load(rendered)[0])
    assert reparsed.model.entries == rules.model.entries
    assert 'Proxy' not in rendered
    assert snippet("DST-PORT,80,443").model.entries[0].expression.matcher == "80,443"


@pytest.mark.parametrize("matcher", [r"^foo\(bar$", r"^foo\)bar$", r"^foo \#bar$", r"^foo\'bar$"])
def test_escaped_regex_structure_survives_nested_and_top_level(matcher):
    for text in (f"DOMAIN-REGEX,{matcher}", f"NOT,((DOMAIN-REGEX,{matcher}))"):
        rules = snippet(text)
        rendered = rules.render("mihomo", "Proxy")
        reparsed = snippet(yaml.safe_load(rendered)[0])
        assert reparsed.model.entries[0].expression == rules.model.entries[0].expression


@pytest.mark.parametrize("parser,limit", [(MIHOMO_CLASSICAL_PARSER, 64), (STASH_CLASSICAL_PARSER, 64), (SURGE_CLASSICAL_PARSER, 10)])
def test_input_logical_depth_has_a_safe_boundary(parser, limit):
    assert snippet(nested_rule(limit), parser=parser)
    with pytest.raises(ConfigError, match=f"exceeds {limit} levels"):
        snippet(nested_rule(limit + 1), parser=parser)
    with pytest.raises(ConfigError, match=f"exceeds {limit} levels"):
        snippet(nested_rule(1000), parser=parser)


@pytest.mark.parametrize("depth,valid", [(10, True), (11, False)])
def test_surge_output_enforces_its_logical_depth(depth, valid):
    result = snippet(nested_rule(depth)).render_result("surge", "Proxy")
    assert bool(result.content) == valid
    assert bool(result.issues) != valid


@pytest.mark.parametrize("target", ["mihomo", "clash", "stash", "surge", "dae"])
@pytest.mark.parametrize("separator", ["\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
@pytest.mark.parametrize("field", ["matcher", "policy", "option", "comment"])
def test_target_rejects_physical_line_separators(target, separator, field):
    expression = Predicate("DOMAIN", "example.test")
    policy = "Proxy"
    if field == "matcher":
        expression = Predicate("DOMAIN", "example" + separator + "test")
    elif field == "policy":
        policy += separator + "DIRECT"
    elif field == "option":
        expression = Predicate("IP-CIDR", "192.0.2.0/24", ("no-resolve" + separator,))
    entries = (RuleComment("# heading" + separator + "bad"),) if field == "comment" else (BoundRule(expression, DefaultParameter()),)
    rules = RuleSet(ParameterizedRuleSet(
        name="test", parameters=("rule",), entries=entries,
        source_context=DialectContext("mihomo", "text"),
    ))
    result = rules.render_result(target, policy)
    assert not result.content
    assert result.issues and result.issues[0].severity.value == "error"


@pytest.mark.parametrize("target", ["mihomo", "clash", "stash", "surge"])
def test_scalar_comments_are_valid_target_comments(target):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(RuleSetInputSelection("mihomo", "domain", "text"))
    parsed = codec.parse(name="test", content=b"// heading\nexample.test\n", context=DialectContext("mihomo", "text"))
    result = parameterize(parsed).render_result(target, "Proxy")
    assert result.content.startswith("# heading\n")
    assert not result.issues
    if target != "surge":
        assert yaml.safe_load(result.content) == ["DOMAIN,example.test,Proxy"]


@pytest.mark.parametrize("value", ["Hit #now", "Hit ;now", "Hit //now", "name'quoted", "name(unclosed"])
def test_surge_inner_token_quotes_preserve_policy_and_option(value):
    rules = snippet("DOMAIN,example.test", parser=SURGE_CLASSICAL_PARSER)
    rendered = rules.render("surge", value)
    assert snippet(rendered, parser=SURGE_CLASSICAL_PARSER).model.entries[0].policy_binding.value == value
    expression = Predicate("DOMAIN", "example.test", ("notification-text=" + value,))
    rules.model = ParameterizedRuleSet(name="test", parameters=("rule",), entries=(BoundRule(expression, DefaultParameter()),), source_context=DialectContext("surge", "text"))
    reparsed = snippet(rules.render("surge", "Proxy"), parser=SURGE_CLASSICAL_PARSER)
    assert reparsed.model.entries[0].expression.options == expression.options
