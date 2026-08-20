from pathlib import Path

import pytest

# These modules protect CLI, adapter, format, security, and transaction behavior.
# Tests that only describe the current internal topology intentionally stay unmarked.
CONTRACT_TEST_MODULES = {
    "test_crypto_age.py": "security",
    "test_example_e2e.py": "cli-artifact",
    "test_filters.py": "template-api",
    "test_legacy_usage_extractor.py": "security",
    "test_mrs.py": "ruleset-input",
    "test_ruleset.py": "ruleset-semantics",
    "test_subio_v2_capability_invariants.py": "target-adapters",
    "test_subio_v2_conversion_regressions.py": "node-conversion",
    "test_subio_v2_emitter_dae.py": "dae-output",
    "test_subio_v2_filters_api.py": "template-api",
    "test_subio_v2_main.py": "cli",
    "test_subio_v2_node_dialect.py": "node-conversion",
    "test_subio_v2_parser_clash.py": "clash-family",
    "test_subio_v2_parser_clash_all_protocols.py": "clash-family",
    "test_subio_v2_parser_clash_combos.py": "clash-family",
    "test_subio_v2_parser_clash_comprehensive.py": "clash-family",
    "test_subio_v2_parser_clash_full_coverage.py": "clash-family",
    "test_subio_v2_parser_subio.py": "subio-v2",
    "test_subio_v2_parser_surge.py": "surge",
    "test_subio_v2_parser_v2rayn.py": "v2rayn",
    "test_subio_v2_platforms.py": "platform-naming",
    "test_subio_v2_processor_common.py": "provider-processing",
    "test_subio_v2_stage0_fixtures.py": "clash-family",
    "test_subio_v2_stage0_regressions.py": "clash-family",
    "test_subio_v2_stage5_protocols.py": "protocol-semantics",
    "test_subio_v2_stage6_registry.py": "protocol-semantics",
    "test_subio_v2_stage7_template_context.py": "template-api",
    "test_subio_v2_stage8_stash_dialect.py": "stash",
    "test_subio_v2_stage9_stash_protocols.py": "stash",
    "test_subio_v2_stage10_stash_mieru_juicity.py": "stash",
    "test_subio_v2_stage11_stash_cross_platform.py": "stash",
    "test_subio_v2_subio_format_docs.py": "subio-v2",
    "test_subio_v2_surge_capabilities.py": "surge",
    "test_subio_v2_surge_codec_invariants.py": "surge",
    "test_subio_v2_surge_cross_platform_protocols.py": "surge",
    "test_subio_v2_surge_fixtures.py": "surge",
    "test_subio_v2_surge_resources.py": "surge-resources",
    "test_subio_v2_surge_roundtrip.py": "surge",
    "test_subio_v2_surge_security.py": "security",
    "test_subio_v2_surge_syntax.py": "surge-syntax",
    "test_subio_v2_template_ruleset.py": "ruleset-template",
    "test_subio_v2_template_ruleset_dae.py": "ruleset-template",
    "test_subio_v2_workflow_engine.py": "workflow",
    "test_subio_v2_workflow_fetch.py": "provider-io",
    "test_subio_v2_workflow_upload.py": "publication",
    "test_program_structure_simplification_contract.py": "structure-contract",
    "test_program_structure_simplification_config.py": "structure-config",
}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "contract: externally observable or adapter-level compatibility contract",
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    test_dir = Path(__file__).parent
    available = {path.name for path in test_dir.glob("test_*.py")}
    declared = set(CONTRACT_TEST_MODULES)
    missing = sorted(declared - available)
    if missing:
        raise pytest.UsageError(
            "Test evidence manifest references missing modules: " + ", ".join(missing)
        )
    for item in items:
        area = CONTRACT_TEST_MODULES.get(item.path.name)
        if area is not None:
            item.add_marker(pytest.mark.contract(area=area))
