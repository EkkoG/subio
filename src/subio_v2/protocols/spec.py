from dataclasses import dataclass

from subio_v2.core.nodes import BaseNode, Protocol


@dataclass(frozen=True)
class ProtocolSpec:
    """One protocol's semantic model and native/user policy."""

    protocol: Protocol
    node_class: type[BaseNode]
    requires_endpoint: bool = True
    user_override_fields: frozenset[str] = frozenset()
    terminal_native_user_override_fields: frozenset[str] = frozenset()
    terminal_native_fields: frozenset[str] = frozenset()
    terminal_native_excluded_fields: frozenset[str] = frozenset()
