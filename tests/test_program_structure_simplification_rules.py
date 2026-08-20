from __future__ import annotations

from pathlib import Path

from subio_v2.rules.parser import (
    MIHOMO_CLASSICAL_PARSER,
    STASH_CLASSICAL_PARSER,
    SURGE_CLASSICAL_PARSER,
)


def test_rule_dialect_specs_own_shared_output_rule_sets():
    assert MIHOMO_CLASSICAL_PARSER.spec.output_rules
    assert STASH_CLASSICAL_PARSER.spec.output_rules
    assert SURGE_CLASSICAL_PARSER.spec.output_rules
    assert "SCRIPT" not in STASH_CLASSICAL_PARSER.spec.output_rules
    assert "SCRIPT" not in SURGE_CLASSICAL_PARSER.spec.output_rules


def test_rule_renderer_no_longer_has_duplicate_platform_rules_table():
    source = (Path(__file__).parents[1] / "src/subio_v2/rules/runtime.py").read_text()
    assert "PLATFORM_RULES" not in source
    assert "_output_rules_for_target" in source


def test_ruleset_input_catalog_is_immutable_and_not_a_mutable_registry():
    source = (Path(__file__).parents[1] / "src/subio_v2/rules/codecs.py").read_text()
    assert "RuleSetInputCodecRegistry" not in source
    assert "class RuleSetInputCodecCatalog" in source
    assert "MappingProxyType" in source
