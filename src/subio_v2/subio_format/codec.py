from __future__ import annotations

import types
from dataclasses import MISSING, fields, is_dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any, Union, get_args, get_origin, get_type_hints

import subio_v2.protocols as protocol_registry
from subio_v2.conversion import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.dialect import DialectContext
from subio_v2.model.nodes import Node, Protocol, USER_OVERRIDE_FIELDS
from subio_v2.subio_format.schema import (
    PUBLIC_NESTED_FIELDS,
    PUBLIC_PROTOCOLS,
    SUBIO_FORMAT_VERSION,
    public_node_fields,
)
from subio_v2.validation import validate_node


class _FieldError(ValueError):
    def __init__(self, field: str, message: str, code: str = "parse.subio.invalid-field"):
        super().__init__(message)
        self.field = field
        self.message = message
        self.code = code


class SubioNodeCodec:
    def decode_document(self, data: Any, source_format: str) -> ParseResult:
        if not isinstance(data, dict):
            return self._fatal(
                "parse.subio.invalid-document",
                "SubIO node document must be an object",
                field=None,
            )
        if "nodes" in data and "proxies" in data:
            return self._fatal(
                "parse.subio.invalid-document",
                "SubIO node document cannot contain both 'nodes' and legacy 'proxies'",
                field=None,
            )

        if "nodes" not in data:
            return self._fatal(
                "parse.subio.missing-nodes",
                "SubIO node document requires a 'nodes' array",
                field="nodes",
            )

        unknown_top_level = sorted(set(data) - {"version", "nodes"})
        if unknown_top_level:
            field = unknown_top_level[0]
            return self._fatal(
                "parse.subio.unknown-field",
                f"Unknown SubIO v1 top-level field '{field}'",
                field=field,
            )
        version = data.get("version")
        if type(version) is not int or version != SUBIO_FORMAT_VERSION:
            return self._fatal(
                "parse.subio.unsupported-version",
                f"Unsupported SubIO node format version; expected {SUBIO_FORMAT_VERSION}",
                field="version",
            )
        nodes_data = data.get("nodes")
        if not isinstance(nodes_data, list):
            return self._fatal(
                "parse.subio.invalid-document",
                "SubIO node document field 'nodes' must be an array",
                field="nodes",
            )

        nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        for index, raw_node in enumerate(nodes_data):
            node, node_issues = self._decode_node(raw_node, index, source_format)
            issues.extend(node_issues)
            if node is not None:
                nodes.append(node)
        return ParseResult(nodes=nodes, issues=issues)

    def _decode_node(
        self, raw_node: Any, index: int, source_format: str
    ) -> tuple[Node | None, list[ConversionIssue]]:
        path = f"nodes[{index}]"
        if not isinstance(raw_node, dict):
            return None, [
                self._issue(
                    "parse.subio.invalid-node",
                    "SubIO node entry must be an object",
                    field=path,
                )
            ]

        name = raw_node.get("name") if isinstance(raw_node.get("name"), str) else None
        raw_type = raw_node.get("type")
        if not isinstance(raw_type, str):
            return None, [
                self._issue(
                    "parse.subio.invalid-field",
                    "SubIO node field 'type' must be a string",
                    field=f"{path}.type",
                    node=name,
                )
            ]
        try:
            protocol = Protocol(raw_type)
        except ValueError:
            protocol = None
        if protocol not in PUBLIC_PROTOCOLS:
            return None, [
                self._issue(
                    "parse.subio.unknown-type",
                    f"Unknown or source-bound SubIO node type '{raw_type}'",
                    field=f"{path}.type",
                    node=name,
                    protocol=raw_type,
                )
            ]
        assert protocol is not None

        allowed_fields = public_node_fields(protocol)
        unknown_fields = sorted(set(raw_node) - allowed_fields)
        if unknown_fields:
            return None, [
                self._issue(
                    "parse.subio.unknown-field",
                    f"Unknown SubIO v1 field '{field}'",
                    field=f"{path}.{field}",
                    node=name,
                    protocol=protocol.value,
                )
                for field in unknown_fields
            ]

        desc = protocol_registry.get(protocol)
        if desc is None:
            return None, [
                self._issue(
                    "parse.subio.unknown-type",
                    f"SubIO node type '{protocol.value}' has no registered model",
                    field=f"{path}.type",
                    node=name,
                    protocol=protocol.value,
                )
            ]

        hints = _type_hints(desc.node_class)
        kwargs: dict[str, Any] = {"type": protocol}
        decode_issues: list[ConversionIssue] = []
        for field_name, value in raw_node.items():
            if field_name == "type":
                continue
            field_path = f"{path}.{field_name}"
            try:
                if field_name == "users":
                    decoded = self._decode_users(value, desc.node_class, field_path)
                else:
                    decoded = self._decode_value(value, hints[field_name], field_path)
                kwargs[field_name] = decoded
            except _FieldError as error:
                decode_issues.append(
                    self._issue(
                        error.code,
                        error.message,
                        field=error.field,
                        node=name,
                        protocol=protocol.value,
                    )
                )
        if decode_issues:
            return None, decode_issues

        if "name" not in kwargs:
            return None, [
                self._issue(
                    "parse.subio.invalid-field",
                    "SubIO node field 'name' is required",
                    field=f"{path}.name",
                    protocol=protocol.value,
                )
            ]
        try:
            node = desc.node_class(**kwargs)
        except (TypeError, ValueError):
            return None, [
                self._issue(
                    "parse.subio.invalid-combination",
                    "SubIO node fields could not construct the requested protocol",
                    field=path,
                    node=name,
                    protocol=protocol.value,
                )
            ]

        node.source_context = DialectContext("subio", source_format)
        validation_issues = [
            self._issue(
                "parse.subio.invalid-combination",
                error.message,
                field=f"{path}.{error.field}",
                node=node.name,
                protocol=protocol.value,
            )
            for error in validate_node(node)
        ]
        if validation_issues:
            return None, validation_issues
        return node, []

    def _decode_users(self, value: Any, node_class: type, path: str) -> Any:
        if not isinstance(value, dict):
            raise _FieldError(path, "SubIO node users must be an object")
        hints = _type_hints(node_class)
        users: dict[str, dict[str, Any]] = {}
        for username, overrides in value.items():
            if not isinstance(username, str) or not username:
                raise _FieldError(path, "SubIO node user names must be non-empty strings")
            user_path = f"{path}.{username}"
            if not isinstance(overrides, dict):
                raise _FieldError(user_path, "SubIO user overrides must be an object")
            decoded_overrides: dict[str, Any] = {}
            for field_name, override in overrides.items():
                if (
                    not isinstance(field_name, str)
                    or field_name not in USER_OVERRIDE_FIELDS
                    or field_name not in hints
                ):
                    raise _FieldError(
                        f"{user_path}.{field_name}",
                        f"SubIO user cannot override node field '{field_name}'",
                        code="parse.subio.unknown-field",
                    )
                decoded_overrides[field_name] = self._decode_value(
                    override, hints[field_name], f"{user_path}.{field_name}"
                )
            users[username] = decoded_overrides
        return users

    def _decode_value(self, value: Any, expected: Any, path: str) -> Any:
        if value is None:
            raise _FieldError(path, "SubIO v1 optional fields must be omitted, not null")
        if expected is Any:
            return self._decode_json_value(value, path)

        origin = get_origin(expected)
        args = get_args(expected)
        if origin in {Union, types.UnionType}:
            alternatives = [arg for arg in args if arg is not type(None)]
            for alternative in alternatives:
                try:
                    return self._decode_value(value, alternative, path)
                except _FieldError:
                    continue
            raise _FieldError(path, f"Invalid value type for '{path}'")
        if origin is list:
            if not isinstance(value, list):
                raise _FieldError(path, f"Field '{path}' must be an array")
            item_type = args[0] if args else Any
            return [
                self._decode_value(item, item_type, f"{path}[{index}]")
                for index, item in enumerate(value)
            ]
        if origin is dict:
            if not isinstance(value, dict):
                raise _FieldError(path, f"Field '{path}' must be an object")
            key_type, value_type = args or (Any, Any)
            decoded: dict[Any, Any] = {}
            for key, item in value.items():
                decoded_key = self._decode_value(key, key_type, f"{path}.<key>")
                decoded[decoded_key] = self._decode_value(
                    item, value_type, f"{path}.{key}"
                )
            return decoded

        if isinstance(expected, type) and issubclass(expected, StrEnum):
            if not isinstance(value, str):
                raise _FieldError(path, f"Field '{path}' must be a string enum")
            try:
                return expected(value)
            except ValueError as exc:
                allowed = ", ".join(item.value for item in expected)
                raise _FieldError(
                    path, f"Field '{path}' must be one of: {allowed}"
                ) from exc
        if isinstance(expected, type) and is_dataclass(expected):
            return self._decode_dataclass(value, expected, path)
        if expected is bool:
            if type(value) is not bool:
                raise _FieldError(path, f"Field '{path}' must be a boolean")
            return value
        if expected is int:
            if type(value) is not int:
                raise _FieldError(path, f"Field '{path}' must be an integer")
            return value
        if expected is str:
            if not isinstance(value, str):
                raise _FieldError(path, f"Field '{path}' must be a string")
            return value
        raise _FieldError(path, f"Field '{path}' uses an unsupported schema type")

    def _decode_dataclass(self, value: Any, cls: type, path: str) -> Any:
        if not isinstance(value, dict):
            raise _FieldError(path, f"Field '{path}' must be an object")
        allowed = PUBLIC_NESTED_FIELDS.get(cls)
        if allowed is None:
            raise _FieldError(path, f"Field '{path}' uses an unsupported object type")
        unknown = sorted(set(value) - allowed)
        if unknown:
            field = unknown[0]
            raise _FieldError(
                f"{path}.{field}",
                f"Unknown SubIO v1 field '{field}'",
                code="parse.subio.unknown-field",
            )

        hints = _type_hints(cls)
        kwargs = {
            field_name: self._decode_value(item, hints[field_name], f"{path}.{field_name}")
            for field_name, item in value.items()
        }
        for item in fields(cls):
            if (
                item.name not in kwargs
                and item.default is MISSING
                and item.default_factory is MISSING
            ):
                raise _FieldError(
                    f"{path}.{item.name}",
                    f"Field '{path}.{item.name}' is required",
                )
        try:
            return cls(**kwargs)
        except (TypeError, ValueError) as exc:
            raise _FieldError(path, f"Field '{path}' has an invalid object value") from exc

    def _decode_json_value(self, value: Any, path: str) -> Any:
        if value is None:
            raise _FieldError(path, "SubIO v1 values must not be null")
        if isinstance(value, (str, bool)) or type(value) in {int, float}:
            return value
        if isinstance(value, list):
            return [
                self._decode_json_value(item, f"{path}[{index}]")
                for index, item in enumerate(value)
            ]
        if isinstance(value, dict):
            decoded: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise _FieldError(path, "SubIO v1 object keys must be strings")
                decoded[key] = self._decode_json_value(item, f"{path}.{key}")
            return decoded
        raise _FieldError(path, f"Field '{path}' must contain JSON-compatible values")

    @staticmethod
    def _fatal(code: str, message: str, field: str | None) -> ParseResult:
        return ParseResult(
            nodes=[],
            issues=[SubioNodeCodec._issue(code, message, field=field)],
        )

    @staticmethod
    def _issue(
        code: str,
        message: str,
        *,
        field: str | None,
        node: str | None = None,
        protocol: str | None = None,
    ) -> ConversionIssue:
        return ConversionIssue(
            severity=IssueSeverity.ERROR,
            node=node,
            protocol=protocol,
            source=None,
            target=None,
            field=field,
            message=message,
            stage="parse",
            code=code,
        )


@lru_cache(maxsize=None)
def _type_hints(cls: type) -> dict[str, Any]:
    return get_type_hints(cls)
