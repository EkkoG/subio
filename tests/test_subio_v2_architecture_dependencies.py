import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_FILES = (
    *sorted((REPO_ROOT / "src" / "subio_v2" / "core").glob("*.py")),
    REPO_ROOT / "src" / "subio_v2" / "protocols" / "definitions.py",
    REPO_ROOT / "src" / "subio_v2" / "protocols" / "user_overrides.py",
)
RULES_FILES = tuple(
    sorted((REPO_ROOT / "src" / "subio_v2" / "rules").glob("*.py"))
)

FORBIDDEN_IMPORTS = (
    "os",
    "pathlib",
    "requests",
    "subprocess",
    "tempfile",
    "urllib",
    "subio_v2.capabilities",
    "subio_v2.clash",
    "subio_v2.infrastructure",
    "subio_v2.emitter",
    "subio_v2.parser",
    "subio_v2.subio_format",
    "subio_v2.adapters.surge",
    "subio_v2.workflow",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _is_forbidden(module: str) -> bool:
    return any(
        module == prefix or module.startswith(f"{prefix}.")
        for prefix in FORBIDDEN_IMPORTS
    )


def test_domain_does_not_depend_on_application_or_infrastructure():
    violations = {
        str(path.relative_to(REPO_ROOT)): sorted(
            module for module in _imports(path) if _is_forbidden(module)
        )
        for path in DOMAIN_FILES
    }
    violations = {path: modules for path, modules in violations.items() if modules}

    assert violations == {}


def test_node_and_rules_models_do_not_import_each_other():
    nodes_imports = _imports(REPO_ROOT / "src" / "subio_v2" / "core" / "nodes.py")
    rules_imports = _imports(REPO_ROOT / "src" / "subio_v2" / "core" / "rule_model.py")

    assert "subio_v2.core.rule_model" not in nodes_imports
    assert "subio_v2.core.nodes" not in rules_imports


def test_rules_package_does_not_depend_on_workflow_or_node_models():
    violations = {
        str(path.relative_to(REPO_ROOT)): sorted(
            module
            for module in _imports(path)
            if module == "subio_v2.workflow"
            or module.startswith("subio_v2.workflow.")
            or module == "subio_v2.core.nodes"
        )
        for path in RULES_FILES
    }
    violations = {path: modules for path, modules in violations.items() if modules}

    assert violations == {}


def test_workflow_services_depend_on_registry_interfaces_not_concrete_adapters():
    workflow_dir = REPO_ROOT / "src" / "subio_v2" / "workflow"
    engine_imports = _imports(workflow_dir / "engine.py")
    provider_imports = _imports(workflow_dir / "providers.py")
    artifact_imports = _imports(workflow_dir / "artifacts.py")

    concrete_prefixes = (
        "subio_v2.adapters.clash_family.parser",
        "subio_v2.adapters.clash_family.parser",
        "subio_v2.parser.subio",
        "subio_v2.adapters.surge.parser",
        "subio_v2.parser.v2rayn",
        "subio_v2.adapters.clash_family.emitter",
        "subio_v2.adapters.clash_family.emitter",
        "subio_v2.adapters.surge.emitter",
        "subio_v2.emitter.dae",
        "subio_v2.emitter.v2rayn",
        "subio_v2.adapters.surge",
        "subio_v2.links",
    )

    assert not {
        module
        for module in engine_imports
        if module.startswith(
            ("subio_v2.parser", "subio_v2.emitter", "subio_v2.processor")
        )
        or module.startswith(concrete_prefixes)
    }
    assert not {
        module for module in provider_imports if module.startswith(concrete_prefixes)
    }
    assert not {
        module for module in artifact_imports if module.startswith(concrete_prefixes)
    }
    assert "subio_v2.adapters.catalog" in provider_imports
    assert "subio_v2.adapters.catalog" in artifact_imports


def test_obsolete_internal_authorities_are_absent():
    obsolete_paths = (
        "src/subio_v2/parser/factory.py",
        "src/subio_v2/emitter/factory.py",
        "src/subio_v2/workflow/ruleset.py",
        "src/subio_v2/workflow/rule_parser.py",
        "src/subio_v2/workflow/ruleset_codec.py",
        "src/subio_v2/workflow/mrs.py",
        "src/subio_v2/capabilities/checker.py",
        "src/subio_v2/capabilities/__init__.py",
        "src/subio_v2/capabilities/definitions.py",
        "src/subio_v2/target_registry.py",
        "src/subio_v2/conversion_service.py",
        "src/subio_v2/emitter/link.py",
        "src/subio_v2/parser/base.py",
    )
    assert all(not (REPO_ROOT / path).exists() for path in obsolete_paths)

    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO_ROOT / "src" / "subio_v2").rglob("*.py")
    )
    for symbol in (
        "PLATFORM_CAPABILITIES",
        "ParserFactory",
        "EmitterFactory",
        "ParserRegistry",
        "EmitterRegistry",
        "_factories",
        "CapabilityChecker",
        "check_node_for_platform",
        "PROTOCOL_NAME_MAP",
        "normalize_protocol_name",
        "is_protocol_supported",
        "get_protocol_capabilities",
        "_TARGET_CONSTRAINTS",
        "ProtocolDescriptor",
        "StructuredProtocolDescriptor",
        "DESCRIPTOR",
        "_PROTOCOL_FIELDS",
        "LINK_CODECS",
        "LINK_BUILDERS",
        "def _parse_vmess",
        "def _parse_ss",
        "def _parse_trojan",
        "def _parse_vless",
        "def _validate_config",
        "def _warn_platform_type_replacements",
        "def parse_nodes",
        "def emit_content",
        "def _raise_emit_error",
        "SURGE_EMITTER_HANDLERS",
        "_HANDLERS",
        "def _parts_",
        "elif p_type",
        "_raise_legacy_emit_error",
        "BaseParser",
    ):
        assert symbol not in production

    engine_source = (
        REPO_ROOT / "src" / "subio_v2" / "workflow" / "engine.py"
    ).read_text(encoding="utf-8")
    for symbol in (
        "def _load_providers",
        "def _fetch_content",
        "def _decode_provider_content",
        "def _generate_artifacts",
        "def _generate_single_artifact",
        "def _write_artifact",
    ):
        assert symbol not in engine_source

    provider_source = (
        REPO_ROOT / "src" / "subio_v2" / "workflow" / "providers.py"
    ).read_text(encoding="utf-8")
    artifact_source = (
        REPO_ROOT / "src" / "subio_v2" / "workflow" / "artifacts.py"
    ).read_text(encoding="utf-8")
    assert 'config.get("provider"' not in provider_source
    assert 'config.get("artifact"' not in artifact_source
