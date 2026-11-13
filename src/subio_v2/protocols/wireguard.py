from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, WireguardNode, WireguardPeer
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    assert isinstance(node, WireguardNode)
    errors: list[NodeValidationError] = []
    if not node.private_key:
        errors.append(
            NodeValidationError(
                field="private_key",
                message="Required field 'private_key' is missing",
            )
        )
    if node.peers is not None and not isinstance(node.peers, list):
        errors.append(
            NodeValidationError(field="peers", message="WireGuard peers must be a list")
        )
    elif node.peers:
        for index, peer in enumerate(node.peers):
            if not isinstance(peer, WireguardPeer):
                errors.append(
                    NodeValidationError(
                        field=f"peers[{index}]",
                        message="WireGuard peer must be an object",
                    )
                )
                continue
            if not peer.server:
                errors.append(
                    NodeValidationError(
                        field=f"peers[{index}].server",
                        message="WireGuard peer requires 'server'",
                    )
                )
            if (
                not isinstance(peer.port, int)
                or isinstance(peer.port, bool)
                or not 1 <= peer.port <= 65535
            ):
                errors.append(
                    NodeValidationError(
                        field=f"peers[{index}].port",
                        message="WireGuard peer port must be between 1 and 65535",
                    )
                )
            for field, value in (
                ("public_key", peer.public_key),
                ("allowed_ips", peer.allowed_ips),
            ):
                if not value:
                    errors.append(
                        NodeValidationError(
                            field=f"peers[{index}].{field}",
                            message=f"WireGuard peer requires '{field}'",
                        )
                    )
    else:
        for field, value in (
            ("server", node.server),
            ("public_key", node.public_key),
        ):
            if not value:
                errors.append(
                    NodeValidationError(
                        field=field,
                        message=f"Required field '{field}' is missing",
                    )
                )
        if (
            not isinstance(node.port, int)
            or isinstance(node.port, bool)
            or not 1 <= node.port <= 65535
        ):
            errors.append(
                NodeValidationError(
                    field="port", message="Port must be between 1 and 65535"
                )
            )
    return errors


SPEC = ProtocolSpec(
    protocol=Protocol.WIREGUARD,
    validator=_validate,
    node_class=WireguardNode,
    requires_endpoint=False,
    user_override_fields=frozenset(
        {"server", "port", "private_key", "public_key", "preshared_key"}
    ),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "private_key", "public_key", "preshared_key"}
    ),
    terminal_native_fields=frozenset(
        {
            "allowed_ips",
            "amnezia_wg_option",
            "dns_servers",
            "interface_ip",
            "interface_ipv6",
            "mtu",
            "peers",
            "persistent_keepalive",
            "preshared_key",
            "private_key",
            "public_key",
            "refresh_server_ip_interval",
            "remote_dns_resolve",
            "reserved",
            "smux",
            "workers",
        }
    ),
)
