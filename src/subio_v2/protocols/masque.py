from __future__ import annotations

from subio_v2.core.nodes import MasqueMode, MasqueNode, Node, Protocol
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if not isinstance(node, MasqueNode):
        return errors
    if node.mode == MasqueMode.FORWARD_PROXY:
        if bool(node.username) != bool(node.password):
            errors.append(
                NodeValidationError(
                    "username",
                    "MASQUE Basic authentication requires both username and password",
                )
            )
        return errors
    for field in ("private_key", "public_key"):
        if not getattr(node, field):
            errors.append(
                NodeValidationError(field, f"MASQUE {node.mode.value} requires {field}")
            )
    if node.mode == MasqueMode.CONNECT_IP and not (
        node.interface_ip or node.interface_ipv6
    ):
        errors.append(
            NodeValidationError(
                "interface_ip",
                "MASQUE CONNECT-IP requires an IPv4 or IPv6 tunnel address",
            )
        )
    if node.mode == MasqueMode.H3_L4_PROXY and node.udp:
        errors.append(
            NodeValidationError("udp", "Mihomo h3-l4proxy mode does not support UDP")
        )
    return errors


SPEC = ProtocolSpec(
    protocol=Protocol.MASQUE,
    validator=_validate,
    node_class=MasqueNode,
    user_override_fields=frozenset(
        {"server", "port", "username", "password", "private_key", "public_key"}
    ),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password", "private_key", "public_key"}
    ),
    terminal_native_fields=frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "connect_uri",
            "cwnd",
            "dns_servers",
            "handshake_timeout",
            "hop_interval",
            "interface_ip",
            "interface_ipv6",
            "mode",
            "mtu",
            "password",
            "ports",
            "private_key",
            "public_key",
            "remote_dns_resolve",
            "smux",
            "tls",
            "transport",
            "username",
        }
    ),
)
