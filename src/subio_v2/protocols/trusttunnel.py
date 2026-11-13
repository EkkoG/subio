from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, TrustTunnelNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if not isinstance(node, TrustTunnelNode):
        return errors
    if node.max_streams is not None and (
        node.max_connections is not None or node.min_streams is not None
    ):
        errors.append(
            NodeValidationError(
                "max_streams",
                "Trust Tunnel max-streams conflicts with max-connections/min-streams",
            )
        )
    if node.quic and node.websocket:
        errors.append(
            NodeValidationError(
                "websocket", "Trust Tunnel QUIC and WebSocket modes conflict"
            )
        )
    return errors


SPEC = ProtocolSpec(
    protocol=Protocol.TRUSTTUNNEL,
    required_fields=("username", "password"),
    validator=_validate,
    node_class=TrustTunnelNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "cwnd",
            "headers",
            "health_check",
            "max_connections",
            "max_streams",
            "min_streams",
            "password",
            "quic",
            "smux",
            "tls",
            "username",
            "websocket",
        }
    ),
)
