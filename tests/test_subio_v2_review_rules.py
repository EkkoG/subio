import pytest
import yaml

from subio_v2.core.dialect import DialectContext
from subio_v2.rules.parser import MIHOMO_CLASSICAL_PARSER, STASH_CLASSICAL_PARSER
from subio_v2.rules.runtime import RuleSet


@pytest.mark.parametrize('matcher', ['foo) -> direct #', 'foo bar', 'foo"bar', "foo'bar", 'foo\\bar'])
def test_remote_matcher_cannot_inject_dae(matcher):
    from tests.test_subio_v2_template_ruleset_dae import make_ruleset, bound
    rules = make_ruleset([bound('DOMAIN-KEYWORD', matcher)])
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
