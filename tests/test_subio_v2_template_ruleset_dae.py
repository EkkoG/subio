from subio_v2.core.dialect import DialectContext
from subio_v2.core.rule_model import (
    BoundRule,
    DefaultParameter,
    LiteralPolicy,
    ParameterizedRuleSet,
    Predicate,
)
from subio_v2.rules.runtime import RuleSet


def make_ruleset(entries):
    return RuleSet(
        ParameterizedRuleSet(
            name="rs",
            parameters=("rule",),
            entries=tuple(entries),
            source_context=DialectContext("mihomo", "text"),
        )
    )


def bound(rule_type, matcher="", binding=None):
    return BoundRule(
        Predicate(rule_type, matcher),
        binding or DefaultParameter(),
    )


def test_dae_macro_renders_function_call_syntax():
    ruleset = make_ruleset(
        [
            bound("DOMAIN", "example.com"),
            bound("DOMAIN-SUFFIX", "cn"),
            bound("DOMAIN-KEYWORD", "apple"),
            bound("IP-CIDR", "1.1.1.0/24"),
            bound("IP-CIDR6", "::1/128"),
            bound("MATCH"),
        ]
    )
    rendered = ruleset.render("dae", "direct")
    assert "domain(full: example.com) -> direct" in rendered
    assert "domain(suffix: cn) -> direct" in rendered
    assert "domain(keyword: apple) -> direct" in rendered
    assert "dip(1.1.1.0/24) -> direct" in rendered
    assert "dip(::1/128) -> direct" in rendered
    assert "fallback: direct" in rendered
    assert "- domain(" not in rendered


def test_dae_unsupported_rule_types_return_issues():
    ruleset = make_ruleset(
        [
            bound("PROCESS-NAME", "curl"),
            bound("DOMAIN", "ok.com"),
        ]
    )
    result = ruleset.render_result("dae", "direct")

    assert result.content == "domain(full: ok.com) -> direct"
    assert [issue.code for issue in result.issues] == [
        "ruleset.unsupported-target-rule"
    ]


def test_dae_explicit_policy_kept():
    ruleset = make_ruleset(
        [
            bound(
                "DOMAIN-SUFFIX",
                "google.com",
                LiteralPolicy("my_proxy"),
            )
        ]
    )
    rendered = ruleset.render("dae", "direct")
    assert "domain(suffix: google.com) -> my_proxy" in rendered
