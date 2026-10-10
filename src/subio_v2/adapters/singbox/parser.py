from __future__ import annotations

import json
from typing import Any

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.singbox.outbound import (
    SINGBOX_OUTBOUND_CODECS_BY_TYPE,
    SingBoxCodecError,
    unsupported_field_code,
)
from subio_v2.adapters.singbox.endpoint import SINGBOX_ENDPOINT_CODECS_BY_TYPE
from subio_v2.core.dialect import DialectContext
from subio_v2.core.results import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.core.validation import validate_node


class SingBoxParser:
    context = DialectContext("sing-box", "json")

    def parse_result(self, content: Any) -> ParseResult:
        if isinstance(content, str):
            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON parse error: {exc}") from exc
        elif isinstance(content, dict):
            data = content
        else:
            raise ValueError("Invalid content type for SingBoxParser")
        if not isinstance(data, dict):
            raise ValueError("Sing-box configuration must be an object")
        if "outbounds" not in data and "endpoints" not in data:
            raise ValueError(
                "Sing-box configuration requires an 'outbounds' or 'endpoints' array"
            )
        outbounds = data.get("outbounds", [])
        endpoints = data.get("endpoints", [])
        if not isinstance(outbounds, list):
            raise ValueError("Sing-box field 'outbounds' must be an array")
        if not isinstance(endpoints, list):
            raise ValueError("Sing-box field 'endpoints' must be an array")

        nodes = []
        issues: list[ConversionIssue] = []
        self._parse_entries(
            outbounds,
            "outbounds",
            SINGBOX_OUTBOUND_CODECS_BY_TYPE,
            nodes,
            issues,
        )
        self._parse_entries(
            endpoints,
            "endpoints",
            SINGBOX_ENDPOINT_CODECS_BY_TYPE,
            nodes,
            issues,
        )
        return ParseResult(nodes=nodes, issues=issues)

    def _parse_entries(self, entries, section, registry, nodes, issues) -> None:
        for index, raw in enumerate(entries):
            path = f"{section}[{index}]"
            if not isinstance(raw, dict):
                issues.append(
                    self._issue(
                        "parse.singbox.invalid-entry",
                        f"Sing-box {section[:-1]} entry must be an object",
                        path,
                    )
                )
                continue
            raw_type = raw.get("type")
            tag = raw.get("tag") if isinstance(raw.get("tag"), str) else None
            if not isinstance(raw_type, str):
                issues.append(
                    self._issue(
                        "parse.singbox.invalid-field",
                        f"Sing-box {section[:-1]} field 'type' must be a string",
                        f"{path}.type",
                        node=tag,
                    )
                )
                continue
            codec = registry.get(raw_type)
            if codec is None:
                issues.append(
                    self._issue(
                        "parse.singbox.unsupported-type",
                        f"Sing-box {section[:-1]} type '{raw_type}' is not supported",
                        f"{path}.type",
                        node=tag,
                        protocol=raw_type,
                    )
                )
                continue
            unknown = sorted(set(raw) - codec.allowed_keys)
            if unknown:
                for field in unknown:
                    code = unsupported_field_code(field)
                    label = "unsafe" if code.endswith("unsafe-field") else "unsupported"
                    issues.append(
                        self._issue(
                            code,
                            f"Sing-box {section[:-1]} field '{field}' is {label}",
                            f"{path}.{field}",
                            node=tag,
                            protocol=raw_type,
                        )
                    )
                continue
            try:
                node = codec.parse(raw)
            except SingBoxCodecError as exc:
                issues.append(
                    self._issue(
                        exc.code,
                        str(exc),
                        f"{path}.{exc.field}",
                        node=tag,
                        protocol=raw_type,
                    )
                )
                continue
            node.source_context = self.context
            validation_errors = validate_node(
                node,
                definition=protocol_registry.get_definition(node.type),
                descriptor=protocol_registry.get(node.type),
            )
            if validation_errors:
                issues.extend(
                    self._issue(
                        "parse.singbox.invalid-combination",
                        error.message,
                        f"{path}.{error.field}",
                        node=node.name,
                        protocol=raw_type,
                    )
                    for error in validation_errors
                )
                continue
            nodes.append(node)

    @staticmethod
    def _issue(
        code: str,
        message: str,
        field: str,
        *,
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
