from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.core.nodes import (
    Node,
    Protocol,
    RejectMode,
    RejectNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_reject(record: SurgeProxyRecord) -> RejectNode:
    return RejectNode(
        name=record.name,
        type=Protocol.REJECT,
        server=None,
        port=None,
        udp=False,
        mode=RejectMode(record.type.lower()),
    )


def check_reject(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, RejectNode):
        return []
    supported_modes = proto_caps.get("modes", set())
    warnings: list[IssueDraft] = []
    if node.mode.value not in supported_modes:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Reject mode '{node.mode.value}' is not supported by surge",
                field="mode",
                code="conversion.unsupported-protocol-variant",
            )
        )
    if node.smux.enabled and "smux" not in proto_caps.get("features", set()):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reject SMUX is not supported by surge",
                field="smux",
                code="conversion.unsupported-protocol-variant",
            )
        )
    return warnings


def emit_reject(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, RejectNode)
    return [node.mode.value]


CODECS = (
    *(
        _spec(
            keyword,
            protocol=Protocol.REJECT,
            check=check_reject,
            udp=SurgeUdpBehavior.UNSUPPORTED,
            parser=parse_reject,
            emitter=emit_reject,
            constraints={
                "modes": {"reject", "reject-drop", "reject-no-drop", "reject-tinygif"}
            },
        )
        for keyword in (
            "reject",
            "reject-drop",
            "reject-no-drop",
            "reject-tinygif",
        )
    ),
)
