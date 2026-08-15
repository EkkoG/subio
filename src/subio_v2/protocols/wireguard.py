from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol, WireguardNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._base import NodeValidationError
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class WireguardDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.WIREGUARD
    clash_type = "wireguard"
    node_class = WireguardNode
    fields = (
        scalar_field(
            "private-key",
            "private_key",
            default="",
            emit_policy=EmitPolicy.ALWAYS,
            required=True,
        ),
        scalar_field(
            "public-key",
            "public_key",
            default="",
            emit_policy=EmitPolicy.TRUTHY,
            required=True,
        ),
        scalar_field(
            "preshared-key",
            "preshared_key",
            aliases=("pre-shared-key",),
            emit_policy=EmitPolicy.TRUTHY,
        ),
        scalar_field("ip", "interface_ip", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("ipv6", "interface_ipv6", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "allowed-ips",
            "allowed_ips",
            decode=lambda value: list(value) if isinstance(value, list) else None,
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("reserved", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("mtu", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("workers", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "persistent-keepalive",
            "persistent_keepalive",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "amnezia-wg-option",
            "amnezia_wg_option",
            emit_policy=EmitPolicy.TRUTHY,
        ),
        scalar_field("peers", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "remote-dns-resolve",
            "remote_dns_resolve",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("dns", "dns_servers", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "refresh-server-ip-interval",
            "refresh_server_ip_interval",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        smux_group(),
    )

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out["udp"] = True

    def validate(self, node: Node) -> list[NodeValidationError]:
        assert isinstance(node, WireguardNode)
        errors: list[NodeValidationError] = []
        if not node.private_key:
            errors.append(
                NodeValidationError(
                    field="private_key",
                    message="Required field 'private_key' is missing",
                )
            )
        if node.peers:
            for index, peer in enumerate(node.peers):
                for key in ("server", "port", "public-key", "allowed-ips"):
                    if not peer.get(key):
                        errors.append(
                            NodeValidationError(
                                field=f"peers[{index}].{key}",
                                message=f"WireGuard peer requires '{key}'",
                            )
                        )
        elif not node.public_key:
            errors.append(
                NodeValidationError(
                    field="public_key", message="Required field 'public_key' is missing"
                )
            )
        return errors


register(WireguardDescriptor())
