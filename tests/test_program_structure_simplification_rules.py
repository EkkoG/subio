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
    assert "get_rule_output_dialect" in source
    assert "_target_form" not in source
    assert "_output_options_for_target" not in source


def test_ruleset_input_catalog_is_immutable_and_not_a_mutable_registry():
    source = (Path(__file__).parents[1] / "src/subio_v2/rules/codecs.py").read_text()
    assert "RuleSetInputCodecRegistry" not in source
    assert "class RuleSetInputCodecCatalog" in source
    assert "MappingProxyType" in source
