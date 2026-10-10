from __future__ import annotations

import json
from typing import Any

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.singbox.outbound import (
    SINGBOX_OUTBOUND_CODECS_BY_TYPE,
    SingBoxCodecError,
    unsupported_field_code,
)
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
        outbounds = data.get("outbounds")
        if not isinstance(outbounds, list):
            raise ValueError("Sing-box configuration requires an 'outbounds' array")

        nodes = []
        issues: list[ConversionIssue] = []
        if data.get("endpoints"):
            issues.append(
                self._issue(
                    "parse.singbox.unsupported-section",
                    "Sing-box endpoints are not supported by this codec boundary",
                    "endpoints",
                )
            )
        for index, raw in enumerate(outbounds):
            path = f"outbounds[{index}]"
            if not isinstance(raw, dict):
                issues.append(
                    self._issue(
                        "parse.singbox.invalid-entry",
                        "Sing-box outbound entry must be an object",
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
                        "Sing-box outbound field 'type' must be a string",
                        f"{path}.type",
                        node=tag,
                    )
                )
                continue
            codec = SINGBOX_OUTBOUND_CODECS_BY_TYPE.get(raw_type)
            if codec is None:
                issues.append(
                    self._issue(
                        "parse.singbox.unsupported-type",
                        f"Sing-box outbound type '{raw_type}' is not supported",
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
                            f"Sing-box outbound field '{field}' is {label}",
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
        return ParseResult(nodes=nodes, issues=issues)

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
