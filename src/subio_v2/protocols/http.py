from __future__ import annotations

from subio_v2.core.nodes import HttpNode, HttpVariant, Node, Protocol
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    if not isinstance(node, HttpNode) or node.variant == HttpVariant.AUTO:
        return []
    expected_tls = node.variant in {HttpVariant.HTTPS, HttpVariant.H2_CONNECT}
    if bool(node.tls and node.tls.enabled) != expected_tls:
        return [NodeValidationError(
            "tls.enabled", "Explicit HTTP variant must agree with TLS enabled state"
        )]
    return []


SPEC = ProtocolSpec(
    protocol=Protocol.HTTP,
    node_class=HttpNode,
    validator=_validate,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "always_use_connect",
            "headers",
            "max_streams",
            "password",
            "tls",
            "username",
            "variant",
        }
    ),
)
