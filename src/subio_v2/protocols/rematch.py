from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, RematchNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if isinstance(node, RematchNode) and (
        node.target_rematch_name is None and node.target_sub_rule is None
    ):
        errors.append(
            NodeValidationError(
                "target_rematch_name",
                "Rematch requires target-rematch-name or target-sub-rule",
            )
        )
    return errors


SPEC = ProtocolSpec(
    protocol=Protocol.REMATCH,
    validator=_validate,
    node_class=RematchNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port"}),
    terminal_native_fields=frozenset(
        {"smux", "target_rematch_name", "target_sub_rule"}
    ),
)
