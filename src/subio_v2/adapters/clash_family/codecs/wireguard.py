from __future__ import annotations

import copy
from typing import Any, Dict

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
)
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol, WireguardNode, WireguardPeer
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.wireguard import SPEC

_PEER_KEYS = {
    "server",
    "port",
    "public-key",
    "pre-shared-key",
    "preshared-key",
    "reserved",
    "allowed-ips",
}


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
                preshared_key=peer.get("pre-shared-key") or peer.get("preshared-key"),
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

    def after_parse(self, node: Node, data: dict[str, Any]) -> Node:
        raw = data.get("peers")
        if isinstance(raw, list):
            unknown = [
                {
                    key: copy.deepcopy(value)
                    for key, value in peer.items()
                    if key not in _PEER_KEYS
                }
                for peer in raw
            ]
            if any(unknown):
                node.source_extensions.setdefault(
                    node.source_context.dialect, {}
                ).update(
                    peers=unknown,
                    semantic_fields=[
                        f"peers[{index}].{key}"
                        for index, peer in enumerate(unknown)
                        for key in peer
                    ],
                )
        return node

    def emit_clash(
        self, node: Node, context: DialectContext | None = None
    ) -> dict[str, Any]:
        context = context or DialectContext("mihomo", "yaml")
        out = super().emit_clash(node, context)
        if (
            node.source_context
            and node.source_context.dialect == context.dialect
            and isinstance(out.get("peers"), list)
        ):
            unknown = node.source_extensions.get(context.dialect, {}).get("peers", [])
            for peer, extra in zip(out["peers"], unknown):
                for key, value in extra.items():
                    if key not in _PEER_KEYS:
                        peer.setdefault(key, copy.deepcopy(value))
        return out

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
        ),
        scalar_field(
            "public-key",
            "public_key",
            default="",
            emit_policy=EmitPolicy.TRUTHY,
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
        if isinstance(node, WireguardNode) and node.peers:
            out.pop("server", None)
            out.pop("port", None)
        out["udp"] = True

    def _check_peers(
        self, node: Node, proto_caps: dict, platform: str
    ) -> list[IssueDraft]:
        if platform == "stash" and isinstance(node, WireguardNode) and node.peers:
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="WireGuard peers cannot be represented by Stash",
                    field="peers",
                    code="conversion.unsupported-platform-field",
                )
            ]
        return []

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        from subio_v2.adapters.checks import wireguard_peer_keepalive

        return wireguard_peer_keepalive(node) + self._check_peers(
            node, proto_caps, platform
        )


CODEC = WireguardCodec()
