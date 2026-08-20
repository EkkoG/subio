from __future__ import annotations

from typing import Any, Dict

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, RejectNode
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import smux_group
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.REJECT,
    node_class=RejectNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port"}),
    terminal_native_fields=frozenset({"mode", "smux"}),
)


class RejectCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.REJECT
    clash_type = "reject"
    target_constraints = {
        "mihomo": {"modes": {"reject"}, "features": {"smux"}},
    }
    fields = (smux_group(),)

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        kwargs["server"] = None
        kwargs["port"] = None
        kwargs["udp"] = False
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out.pop("server", None)
        out.pop("port", None)
        out.pop("udp", None)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, RejectNode):
            return []
        supported_modes = proto_caps.get("modes", set())
        warnings: list[IssueDraft] = []
        if node.mode.value not in supported_modes:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=(
                        f"Reject mode '{node.mode.value}' is not supported by {platform}"
                    ),
                    field="mode",
                    code="conversion.unsupported-protocol-variant",
                )
            )
        if node.smux.enabled and "smux" not in proto_caps.get("features", set()):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Reject SMUX is not supported by {platform}",
                    field="smux",
                    code="conversion.unsupported-protocol-variant",
                )
            )
        return warnings


CODEC = RejectCodec()
