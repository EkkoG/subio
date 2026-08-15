from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol, WireguardNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
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


register(WireguardDescriptor())
