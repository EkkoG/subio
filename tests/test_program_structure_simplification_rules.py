from __future__ import annotations

from pathlib import Path

from subio_v2.rules.output import RULE_OUTPUT_DIALECTS


def test_rule_dialect_specs_own_shared_output_rule_sets():
    assert RULE_OUTPUT_DIALECTS["mihomo"].rule_types
    assert RULE_OUTPUT_DIALECTS["stash"].rule_types
    assert RULE_OUTPUT_DIALECTS["surge"].rule_types
    assert "src" in RULE_OUTPUT_DIALECTS["mihomo"].option_names
    assert "no-track" in RULE_OUTPUT_DIALECTS["stash"].option_names
    assert "extended-matching" in RULE_OUTPUT_DIALECTS["surge"].option_names
    assert "SCRIPT" not in RULE_OUTPUT_DIALECTS["stash"].rule_types
    assert "SCRIPT" not in RULE_OUTPUT_DIALECTS["surge"].rule_types
    assert RULE_OUTPUT_DIALECTS["clash"].rule_types
    assert RULE_OUTPUT_DIALECTS["dae"].rule_types


def test_rule_renderer_no_longer_has_duplicate_platform_rules_table():
    source = (Path(__file__).parents[1] / "src/subio_v2/rules/runtime.py").read_text()
    assert "PLATFORM_RULES" not in source
    assert "get_rule_output_target" in source
    assert 'platform == "sing-box"' not in source
    assert "_target_form" not in source
    assert "_output_options_for_target" not in source


def test_dae_value_checks_belong_to_the_selected_output_contract():
    from dataclasses import replace

    from subio_v2.core.dialect import DialectContext
    from subio_v2.core.rule_model import Predicate

    dialect = replace(RULE_OUTPUT_DIALECTS["dae"], name="test-target")
    content, issues = dialect.render(
        source="test",
        expression=Predicate("DOMAIN", "example.com) -> injected"),
        source_context=DialectContext("mihomo", "text"),
        policy="Proxy",
    )
    assert content is None
    assert issues[0].code == "ruleset.invalid-target-value"
    assert issues[0].target == "test-target"


def test_ruleset_input_catalog_is_immutable_and_not_a_mutable_registry():
    source = (Path(__file__).parents[1] / "src/subio_v2/rules/codecs.py").read_text()
    assert "RuleSetInputCodecRegistry" not in source
    assert "class RuleSetInputCodecCatalog" in source
    assert "MappingProxyType" in source
