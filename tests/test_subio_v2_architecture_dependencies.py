import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_FILES = (
    *sorted((REPO_ROOT / "src" / "subio_v2" / "model").glob("*.py")),
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
    "subio_v2.crypto",
    "subio_v2.emitter",
    "subio_v2.parser",
    "subio_v2.subio_format",
    "subio_v2.surge",
    "subio_v2.utils.logger",
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
    nodes_imports = _imports(REPO_ROOT / "src" / "subio_v2" / "model" / "nodes.py")
    rules_imports = _imports(REPO_ROOT / "src" / "subio_v2" / "model" / "rules.py")

    assert "subio_v2.model.rules" not in nodes_imports
    assert "subio_v2.model.nodes" not in rules_imports


def test_rules_package_does_not_depend_on_workflow_or_node_models():
    violations = {
        str(path.relative_to(REPO_ROOT)): sorted(
            module
            for module in _imports(path)
            if module == "subio_v2.workflow"
            or module.startswith("subio_v2.workflow.")
            or module == "subio_v2.model.nodes"
        )
        for path in RULES_FILES
    }
    violations = {path: modules for path, modules in violations.items() if modules}

    assert violations == {}


def test_obsolete_internal_authorities_are_absent():
    obsolete_paths = (
        "src/subio_v2/parser/factory.py",
        "src/subio_v2/emitter/factory.py",
        "src/subio_v2/workflow/ruleset.py",
        "src/subio_v2/workflow/rule_parser.py",
        "src/subio_v2/workflow/ruleset_codec.py",
        "src/subio_v2/workflow/mrs.py",
        "src/subio_v2/capabilities/checker.py",
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
        "SURGE_EMITTER_HANDLERS",
        "_HANDLERS",
        "def _parts_",
        "elif p_type",
        "_raise_legacy_emit_error",
    ):
        assert symbol not in production
