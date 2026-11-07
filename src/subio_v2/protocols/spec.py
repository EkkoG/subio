from collections.abc import Callable
from dataclasses import dataclass

from subio_v2.core.nodes import BaseNode, Node, Protocol
from subio_v2.core.validation import NodeValidationError


@dataclass(frozen=True)
class ProtocolSpec:
    """One protocol's model, semantic validation and native/user policy."""

    protocol: Protocol
    node_class: type[BaseNode]
    requires_endpoint: bool = True
    required_fields: tuple[str, ...] = ()
    validator: Callable[[Node], list[NodeValidationError]] | None = None
    user_override_fields: frozenset[str] = frozenset()
    terminal_native_user_override_fields: frozenset[str] = frozenset()
    terminal_native_fields: frozenset[str] = frozenset()
    terminal_native_excluded_fields: frozenset[str] = frozenset()
    native_public: bool = True

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = [
            NodeValidationError(field, f"Required field '{field}' is missing")
            for field in self.required_fields
            if getattr(node, field) is None or getattr(node, field) == ""
        ]
        if self.validator is not None:
            errors.extend(self.validator(node))
        return errors
