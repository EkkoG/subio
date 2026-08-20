from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol as TypingProtocol

from subio_v2.core.nodes import Node, RejectMode, RejectNode


@dataclass(frozen=True)
class NodeValidationError:
    field: str
    message: str


class ProtocolDefinitionLike(TypingProtocol):
    requires_endpoint: bool


class DescriptorValidatorLike(TypingProtocol):
    def validate(self, node: Node) -> list[NodeValidationError]: ...


def validate_node(
    node: Node,
    *,
    definition: ProtocolDefinitionLike | None = None,
    descriptor: DescriptorValidatorLike | None = None,
) -> list[NodeValidationError]:
    """Validate generic node structure plus explicitly supplied protocol semantics."""

    errors: list[NodeValidationError] = []
    if not node.name:
        errors.append(NodeValidationError("name", "Node name is required"))
    if isinstance(node, RejectNode) and not isinstance(node.mode, RejectMode):
        errors.append(NodeValidationError("mode", "Reject mode is invalid"))

    if definition is not None and definition.requires_endpoint:
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

    if descriptor is not None:
        errors.extend(descriptor.validate(node))
    return errors
