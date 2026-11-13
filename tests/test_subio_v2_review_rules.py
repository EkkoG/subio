import pytest
import yaml
import json

from subio_v2.core.dialect import DialectContext
from subio_v2.rules.parser import MIHOMO_CLASSICAL_PARSER, STASH_CLASSICAL_PARSER
from subio_v2.rules.runtime import RuleSet
from subio_v2.rules.codecs import DEFAULT_RULESET_CODEC_REGISTRY, RuleSetInputSelection
from subio_v2.core.errors import ConfigError
from tests.test_ruleset import parameterize


@pytest.mark.parametrize('matcher', ['foo) -> direct #', 'foo bar', 'foo"bar', "foo'bar", 'foo\\bar'])
def test_remote_matcher_cannot_inject_dae(matcher):
    parsed = MIHOMO_CLASSICAL_PARSER.parse_headless(name='remote',
        lines=[(1, 'DOMAIN-KEYWORD,' + json.dumps(matcher))], source_context=DialectContext('mihomo', 'text'))
    rules = parameterize(parsed)
    result = rules.render_result('dae', 'Proxy')
    assert not result.content
    assert result.issues[0].code == 'ruleset.invalid-target-value'


@pytest.mark.parametrize('policy', ['Proxy #direct', 'Proxy) -> direct', 'Proxy Auto', 'Proxy\n#'])
def test_dae_policy_cannot_inject_syntax(policy):
    from tests.test_subio_v2_template_ruleset_dae import make_ruleset, bound
    result = make_ruleset([bound('MATCH')]).render_result('dae', policy)
    assert not result.content and result.issues[0].severity.value == 'error'


@pytest.mark.parametrize('target', ['mihomo', 'clash', 'stash'])
@pytest.mark.parametrize('policy', ['Proxy: Auto', 'Proxy #private', 'Proxy "quoted"', 'Proxy\\path'])
def test_complete_rule_is_one_yaml_string(target, policy):
    from tests.test_subio_v2_template_ruleset_dae import make_ruleset, bound
    result = make_ruleset([bound('DOMAIN', 'example.com')]).render_result(target, policy)
    assert not result.issues
    value = yaml.safe_load(result.content)
    assert isinstance(value[0], str)
    assert policy in value[0].replace('\\\\', '\\').replace('\\"', '"')


def test_stash_match_options_survive_parse_and_render():
    from subio_v2.core.rule_model import ParameterizedRuleSet
    parsed = STASH_CLASSICAL_PARSER.parse_snippet(name='test', parameter_names=('rule',),
        content='MATCH,no-track', source_context=DialectContext('stash', 'text'))
    assert parsed.entries[0].expression.options == ('no-track',)
    rules = RuleSet(ParameterizedRuleSet(name='test', parameters=('rule',),
        entries=parsed.entries,
        source_context=DialectContext('stash', 'text')))
    result = rules.render_result('stash', 'Proxy')
    assert result.content == '- MATCH,Proxy,no-track'
    assert not result.issues
    assert rules.render_result('mihomo', 'Proxy').issues


@pytest.mark.parametrize('behavior', ['classical', 'domain', 'ipcidr'])
@pytest.mark.parametrize('separator', ['\n', '\r\n', '\u0085', '\u2028'])
def test_yaml_multiline_comment_cannot_add_routes(behavior, separator):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(RuleSetInputSelection('mihomo', behavior, 'yaml'))
    content = yaml.safe_dump({'payload': ['# harmless' + separator + 'fallback: direct']}).encode()
    with pytest.raises(ConfigError, match='single line'):
        codec.parse(name='remote', content=content, context=DialectContext('mihomo', 'yaml'))


@pytest.mark.parametrize('matcher', ['fe80::%x/64', 'fe80::%x) -> direct #/64'])
def test_ipv6_scope_cannot_enter_dae_syntax(matcher):
    codec = DEFAULT_RULESET_CODEC_REGISTRY.get(RuleSetInputSelection('mihomo', 'classical', 'text'))
    parsed = codec.parse(name='remote', content=('IP-CIDR6,' + json.dumps(matcher)).encode(), context=DialectContext('mihomo', 'text'))
    result = parameterize(parsed).render_result('dae', 'Proxy')
    assert not result.content and result.issues[0].code == 'ruleset.invalid-target-value'


@pytest.mark.parametrize('target', ['mihomo', 'clash', 'stash'])
@pytest.mark.parametrize('separator', ['\u0085', '\u2028', '\u2029'])
def test_yaml_line_characters_preserve_the_exact_policy(target, separator):
    from tests.test_subio_v2_template_ruleset_dae import make_ruleset, bound
    policy = 'Proxy' + separator + 'Private'
    result = make_ruleset([bound('DOMAIN', 'example.test')]).render_result(target, policy)
    assert not result.issues
    assert yaml.safe_load(result.content) == ['DOMAIN,example.test,' + policy]
