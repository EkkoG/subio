from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol, WireguardNode, WireguardPeer
from subio_v2.protocols._base import NodeValidationError, StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.WIREGUARD,
    node_class=WireguardNode,
    user_override_fields=frozenset({"server", "port", "private_key", "public_key", "preshared_key"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "private_key", "public_key", "preshared_key"}),
    terminal_native_fields=frozenset({"allowed_ips", "amnezia_wg_option", "dns_servers", "interface_ip", "interface_ipv6", "mtu", "peers", "persistent_keepalive", "preshared_key", "private_key", "public_key", "refresh_server_ip_interval", "remote_dns_resolve", "reserved", "smux", "workers"}),
)


def _decode_peers(value: Any) -> list[WireguardPeer] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("WireGuard peers must be a list")
    peers: list[WireguardPeer] = []
    for index, peer in enumerate(value):
        if not isinstance(peer, dict):
            raise ValueError(f"WireGuard peer {index} must be an object")
        allowed_ips = peer.get("allowed-ips")
        if not isinstance(allowed_ips, list):
            allowed_ips = []
        peers.append(
            WireguardPeer(
                server=peer.get("server", ""),
                port=peer.get("port", 0),
                public_key=peer.get("public-key", ""),
                preshared_key=peer.get("pre-shared-key")
                or peer.get("preshared-key"),
                reserved=peer.get("reserved"),
                allowed_ips=allowed_ips,
            )
        )
    return peers


def _encode_peers(value: list[WireguardPeer] | None) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    peers: list[dict[str, Any]] = []
    for peer in value:
        encoded: dict[str, Any] = {
            "server": peer.server,
            "port": peer.port,
            "public-key": peer.public_key,
            "allowed-ips": peer.allowed_ips,
        }
        if peer.preshared_key:
            encoded["pre-shared-key"] = peer.preshared_key
        if peer.reserved:
            encoded["reserved"] = peer.reserved
        peers.append(encoded)
    return peers


class WireguardCodec(StructuredClashProtocolCodec):
    spec = SPEC
    stash_input_aliases = {"keepalive": "persistent-keepalive"}
    stash_output_aliases = {"persistent-keepalive": "keepalive"}
    protocol = Protocol.WIREGUARD
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "wireguard"
    dialect_fields = {
        "stash": stash_fields(
            "ip",
            "ipv6",
            "private-key",
            "public-key",
            "preshared-key",
            "dns",
            "mtu",
            "reserved",
            "keepalive",
        )
    }
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
        scalar_field(
            "peers",
            decode=_decode_peers,
            encode=_encode_peers,
            emit_policy=EmitPolicy.TRUTHY,
        ),
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
                for field, value in (
                    ("server", peer.server),
                    ("port", peer.port),
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
        elif not node.public_key:
            errors.append(
                NodeValidationError(
                    field="public_key", message="Required field 'public_key' is missing"
                )
            )
        return errors


CODEC = WireguardCodec()
