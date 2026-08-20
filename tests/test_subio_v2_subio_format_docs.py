import re
import types
from dataclasses import is_dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

import subio_v2.protocols as protocol_registry
from subio_v2.core.nodes import Protocol
from subio_v2.adapters.subio.parser import SubioParser
from subio_v2.adapters.subio.schema import (
    PUBLIC_NESTED_FIELDS,
    PUBLIC_PROTOCOLS,
    public_mapping_spec,
    public_user_override_fields,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
FORMAT_DOC_PATH = REPOSITORY_ROOT / "docs" / "subio_node_format.md"
EXAMPLE_PROVIDER_DIR = REPOSITORY_ROOT / "example" / "provider"


def _document() -> str:
    return FORMAT_DOC_PATH.read_text(encoding="utf-8")


def _type_label(expected: Any) -> str:
    origin = get_origin(expected)
    args = get_args(expected)
    if origin in {Union, types.UnionType}:
        alternatives = [arg for arg in args if arg is not type(None)]
        labels = {_type_label(arg) for arg in alternatives}
        if labels == {"string", "string[]"}:
            return "string 或 string[]"
        if labels == {"string", "string enum"}:
            return "string"
        assert len(labels) == 1, expected
        return labels.pop()
    if origin is list:
        item_label = _type_label(args[0])
        return "object[]" if item_label == "object" else f"{item_label}[]"
    if origin is dict:
        key_type, value_type = args
        if key_type is str and value_type is str:
            return "object<string,string>"
        return "object"
    if isinstance(expected, type) and issubclass(expected, StrEnum):
        return "string enum"
    if isinstance(expected, type) and is_dataclass(expected):
        return "object"
    if expected is str:
        return "string"
    if expected is int:
        return "integer"
    if expected is bool:
        return "boolean"
    if expected is Any:
        return "JSON value"
    raise AssertionError(f"Unsupported documented type: {expected}")


def _table_rows(body: str) -> dict[str, tuple[str, str]]:
    rows = re.findall(r"^\| `([^`]+)` \| ([^|]+?) \| ([^|]+?) \|", body, re.MULTILINE)
    return {
        name: (type_name.strip(), default.strip()) for name, type_name, default in rows
    }


def test_subio_native_examples_follow_v2_contract():
    expected_counts = {
        "self.toml": 4,
        "nodes.json5": 2,
        "multiuser.yml": 3,
    }
    parser = SubioParser()

    for filename, expected_count in expected_counts.items():
        result = parser.parse_result(
            (EXAMPLE_PROVIDER_DIR / filename).read_text(encoding="utf-8")
        )
        assert result.issues == [], filename
        assert len(result.nodes) == expected_count, filename


def test_subio_format_document_examples_cover_every_public_protocol():
    examples = re.findall(
        r"<!-- subio-example:([^ ]+) -->\s*```toml\n(.*?)```\s*"
        r"<!-- /subio-example -->",
        _document(),
        re.DOTALL,
    )
    assert {name for name, _ in examples} == {
        protocol.value for protocol in PUBLIC_PROTOCOLS
    }

    parser = SubioParser()
    for name, content in examples:
        result = parser.parse_result(content)
        assert result.issues == [], (name, result.issues)
        assert result.nodes, name
        assert {node.type.value for node in result.nodes} == {name}


def test_subio_format_document_protocol_fields_match_runtime_contract():
    tables = re.findall(
        r"<!-- protocol-fields:([^ ]+) -->\s*(.*?)\s*"
        r"<!-- /protocol-fields -->",
        _document(),
        re.DOTALL,
    )
    assert {name for name, _ in tables} == {
        protocol.value for protocol in PUBLIC_PROTOCOLS
    }

    for name, body in tables:
        protocol = Protocol(name)
        descriptor = protocol_registry.get(protocol)
        assert descriptor is not None
        hints = get_type_hints(descriptor.node_class)
        rows = _table_rows(body)
        assert set(rows) == descriptor.definition.terminal_native_fields, name
        for field_name, (documented_type, documented_default) in rows.items():
            expected_type = _type_label(hints[field_name])
            allowed_types = {expected_type}
            if expected_type == "string":
                allowed_types.add("string enum")
            if expected_type == "integer":
                allowed_types.add("integer enum")
            assert documented_type in allowed_types, (name, field_name)
            assert documented_default, (name, field_name)


def test_subio_format_document_nested_fields_match_runtime_contract():
    tables = dict(
        re.findall(
            r"<!-- nested-fields:([^ ]+) -->\s*(.*?)\s*"
            r"<!-- /nested-fields -->",
            _document(),
            re.DOTALL,
        )
    )
    assert set(tables) == {cls.__name__ for cls in PUBLIC_NESTED_FIELDS}

    for cls, public_fields in PUBLIC_NESTED_FIELDS.items():
        hints = get_type_hints(cls)
        rows = _table_rows(tables[cls.__name__])
        assert set(rows) == public_fields, cls.__name__
        for field_name, (documented_type, documented_default) in rows.items():
            expected_type = (
                "object"
                if public_mapping_spec(cls, field_name) is not None
                else _type_label(hints[field_name])
            )
            allowed_types = {expected_type}
            if expected_type == "string":
                allowed_types.add("string enum")
            if expected_type == "integer":
                allowed_types.add("integer enum")
            assert documented_type in allowed_types, (cls.__name__, field_name)
            assert documented_default, (cls.__name__, field_name)


def test_subio_format_document_lists_exact_user_override_fields():
    document = _document()
    headings = list(re.finditer(r"^### 6\.\d+ `([^`]+)`$", document, re.MULTILINE))
    assert {match.group(1) for match in headings} == {
        protocol.value for protocol in PUBLIC_PROTOCOLS
    }

    for index, heading in enumerate(headings):
        end = (
            headings[index + 1].start() if index + 1 < len(headings) else len(document)
        )
        body = document[heading.end() : end]
        match = re.search(r"可按用户覆盖：([^。]+)。", body)
        assert match is not None, heading.group(1)
        documented = set(re.findall(r"`([^`]+)`", match.group(1)))
        expected = public_user_override_fields(Protocol(heading.group(1)))
        assert documented == expected, heading.group(1)
