from __future__ import annotations

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import Node, RejectMode, RejectNode
from subio_v2.protocols._base import NodeValidationError


def validate_node(node: Node) -> list[NodeValidationError]:
    """Validate target-independent node structure and protocol semantics."""

    errors: list[NodeValidationError] = []
    if not node.name:
        errors.append(NodeValidationError("name", "Node name is required"))
    if isinstance(node, RejectNode) and not isinstance(node.mode, RejectMode):
        errors.append(NodeValidationError("mode", "Reject mode is invalid"))

    desc = protocol_registry.get(node.type)
    if desc is None:
        return errors

    if desc.requires_endpoint:
        if not node.server:
            errors.append(NodeValidationError("server", "Server is required"))
        if (
            not isinstance(node.port, int)
            or isinstance(node.port, bool)
            or not 1 <= node.port <= 65535
        ):
            errors.append(
                NodeValidationError(
                    "port", f"Port must be between 1 and 65535, got {node.port!r}"
                )
            )

    errors.extend(desc.validate(node))
    return errors
