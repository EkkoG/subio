from __future__ import annotations

import copy
from typing import Any, Dict

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.dialect import DialectContext
from subio_v2.model.nodes import (
    MieruHandshakeMode,
    MieruMultiplexing,
    MieruNode,
    MieruTransport,
    Node,
    Protocol,
)
from subio_v2.protocols._base import NodeValidationError, StructuredClashProtocolCodec
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


def _decode_optional_enum(enum_type: type, value: Any) -> Any:
    return None if value is None else enum_type(value)


def _encode_enum(value: Any) -> str:
    return value.value


class MieruCodec(StructuredClashProtocolCodec):
    protocol = Protocol.MIERU
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "mieru"
    target_constraints = {
        "mihomo": {
            "transports": {"TCP", "UDP"},
            "multiplexing": {
                "MULTIPLEXING_DEFAULT",
                "MULTIPLEXING_OFF",
                "MULTIPLEXING_LOW",
                "MULTIPLEXING_MIDDLE",
                "MULTIPLEXING_HIGH",
            },
            "handshake_modes": {
                "HANDSHAKE_DEFAULT",
                "HANDSHAKE_STANDARD",
                "HANDSHAKE_NO_WAIT",
            },
            "features": {"smux", "traffic-pattern"},
        },
        "stash": {
            "transports": {"TCP"},
            "multiplexing": set(),
            "handshake_modes": set(),
        },
    }
    fields = (
        scalar_field("port-range", "port_range", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "transport",
            default=None,
            decode=lambda value: _decode_optional_enum(MieruTransport, value),
            encode=_encode_enum,
            emit_policy=EmitPolicy.NOT_NONE,
            required=True,
        ),
        scalar_field(
            "username", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field(
            "multiplexing",
            default=None,
            decode=lambda value: _decode_optional_enum(MieruMultiplexing, value),
            encode=_encode_enum,
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "handshake-mode",
            "handshake_mode",
            default=None,
            decode=lambda value: _decode_optional_enum(MieruHandshakeMode, value),
            encode=_encode_enum,
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "traffic-pattern", "traffic_pattern", emit_policy=EmitPolicy.NOT_NONE
        ),
        smux_group(),
    )

    def parse_clash(
        self, data: Dict[str, Any], context: DialectContext | None = None
    ) -> Node:
        normalized = copy.deepcopy(data)
        port = normalized.get("port")
        if isinstance(port, str) and "-" in port and "port-range" not in normalized:
            normalized["port-range"] = port
            normalized.pop("port")
        return super().parse_clash(normalized, context)

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        if "port" not in data:
            kwargs["port"] = None
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        if node.port is None:
            out.pop("port", None)

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, MieruNode):
            return errors
        if not isinstance(node.server, str) or not node.server:
            errors.append(NodeValidationError("server", "Server is required"))

        has_port = node.port is not None
        has_port_range = node.port_range not in {None, ""}
        if has_port == has_port_range:
            errors.append(
                NodeValidationError(
                    "port_range", "Mieru requires exactly one of port or port-range"
                )
            )
            return errors

        if has_port and (
            not isinstance(node.port, int)
            or isinstance(node.port, bool)
            or not 1 <= node.port <= 65535
        ):
            errors.append(
                NodeValidationError(
                    "port", f"Port must be between 1 and 65535, got {node.port!r}"
                )
            )
        if has_port_range and not self._valid_port_range(node.port_range):
            errors.append(
                NodeValidationError(
                    "port_range", f"Invalid Mieru port range: {node.port_range!r}"
                )
            )
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, MieruNode):
            return []
        warnings: list[IssueDraft] = []
        checks = (
            ("transport", node.transport, proto_caps.get("transports", set())),
            (
                "multiplexing",
                node.multiplexing,
                proto_caps.get("multiplexing", set()),
            ),
            (
                "handshake_mode",
                node.handshake_mode,
                proto_caps.get("handshake_modes", set()),
            ),
        )
        for field, value, supported in checks:
            if value is not None and value.value not in supported:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Mieru {field} '{value.value}' is not supported by "
                            f"{platform}"
                        ),
                        field=field,
                        code="conversion.unsupported-protocol-variant",
                    )
                )
        if node.traffic_pattern and "traffic-pattern" not in proto_caps.get(
            "features", set()
        ):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Mieru traffic-pattern is not supported by {platform}",
                    field="traffic_pattern",
                    code="conversion.unsupported-protocol-variant",
                )
            )
        return warnings

    @staticmethod
    def _valid_port_range(value: str | None) -> bool:
        if value is None:
            return False
        parts = value.split("-", 1)
        if not all(part.isdigit() for part in parts):
            return False
        start = int(parts[0])
        end = int(parts[-1])
        return 1 <= start <= end <= 65535


CODEC = MieruCodec()
