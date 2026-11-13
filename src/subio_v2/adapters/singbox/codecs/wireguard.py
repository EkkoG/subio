from __future__ import annotations

from ipaddress import ip_interface
from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxEndpointCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _COMMON_KEYS,
    _ROUTING_MARK_MAX,
    SingBoxCodecError,
    _common_kwargs,
    _optional_int,
    _optional_string,
    _string_or_list,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _ENDPOINT_COMMON_NODE_FIELDS as _COMMON_NODE_FIELDS,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    WireguardNode,
    WireguardPeer,
)
from subio_v2.core.results import IssueDraft

_WIREGUARD_KEYS = _COMMON_KEYS | frozenset(
    {"address", "private_key", "peers", "mtu", "workers"}
)


_WIREGUARD_PEER_KEYS = frozenset(
    {"address", "port", "public_key", "pre_shared_key", "allowed_ips", "reserved"}
)


def _collapse(values: list[str]) -> str | list[str] | None:
    if not values:
        return None
    return values[0] if len(values) == 1 else values


def _node_addresses(node: WireguardNode) -> list[tuple[str, int]] | None:
    addresses: list[tuple[str, int]] = []
    for value, expected_version in (
        (node.interface_ip, 4),
        (node.interface_ipv6, 6),
    ):
        values = [value] if isinstance(value, str) else value
        if values is None:
            continue
        if not isinstance(values, list) or not all(
            isinstance(item, str) for item in values
        ):
            return None
        for item in values:
            try:
                version = ip_interface(item).version
            except ValueError:
                return None
            if version != expected_version:
                return None
            addresses.append((item, version))
    return addresses


def _parse_addresses(
    data: dict[str, Any],
) -> tuple[str | list[str] | None, str | list[str] | None]:
    addresses = _string_or_list(data, "address") or []
    ipv4: list[str] = []
    ipv6: list[str] = []
    for value in addresses:
        try:
            version = ip_interface(value).version
        except ValueError as exc:
            raise SingBoxCodecError(
                "address",
                "Sing-box WireGuard address must be an IP address or prefix",
                "parse.singbox.invalid-field",
            ) from exc
        (ipv4 if version == 4 else ipv6).append(value)
    return _collapse(ipv4), _collapse(ipv6)


def _parse_peer(data: Any, index: int) -> WireguardPeer:
    field = f"peers[{index}]"
    if not isinstance(data, dict):
        raise SingBoxCodecError(
            field,
            "Sing-box WireGuard peer must be an object",
            "parse.singbox.invalid-field",
        )
    unknown = sorted(set(data) - _WIREGUARD_PEER_KEYS)
    if unknown:
        raise SingBoxCodecError(
            f"{field}.{unknown[0]}",
            f"Sing-box WireGuard peer field '{unknown[0]}' is not supported",
            "parse.singbox.unsupported-field",
        )
    try:
        address = _optional_string(data, "address")
        port = _optional_int(data, "port")
        public_key = _optional_string(data, "public_key")
        allowed_ips = _string_or_list(data, "allowed_ips")
        preshared_key = _optional_string(data, "pre_shared_key")
    except SingBoxCodecError as exc:
        raise SingBoxCodecError(f"{field}.{exc.field}", str(exc), exc.code) from exc
    for key, value in (
        ("address", address),
        ("port", port),
        ("public_key", public_key),
        ("allowed_ips", allowed_ips),
    ):
        if not value:
            raise SingBoxCodecError(
                f"{field}.{key}",
                f"Sing-box WireGuard peer requires '{key}'",
                "parse.singbox.invalid-field",
            )
    if not 1 <= port <= 65535:
        raise SingBoxCodecError(
            f"{field}.port",
            "Sing-box WireGuard peer port must be between 1 and 65535",
            "parse.singbox.invalid-field",
        )
    reserved = data.get("reserved")
    if reserved is not None:
        if not isinstance(reserved, list) or any(
            type(value) is not int or not 0 <= value <= 255 for value in reserved
        ):
            raise SingBoxCodecError(
                f"{field}.reserved",
                "Sing-box WireGuard reserved must be a byte array",
                "parse.singbox.unsupported-field",
            )
        reserved = list(reserved)
    return WireguardPeer(
        server=address,
        port=port,
        public_key=public_key,
        preshared_key=preshared_key,
        allowed_ips=allowed_ips,
        reserved=reserved,
    )


class SingBoxWireguardEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "wireguard"
    protocol = Protocol.WIREGUARD
    node_class = WireguardNode
    allowed_keys = _WIREGUARD_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {"private_key", "interface_ip", "interface_ipv6", "mtu", "workers", "peers"}
    )
    expected_udp = True

    def check(self, node: Node) -> list[IssueDraft]:
        from subio_v2.adapters.checks import wireguard_peer_keepalive

        return super().check(node) + wireguard_peer_keepalive(node)

    def parse(self, data: dict[str, Any]) -> WireguardNode:
        peers = data.get("peers")
        if not isinstance(peers, list) or not peers:
            raise SingBoxCodecError(
                "peers",
                "Sing-box WireGuard endpoint requires a non-empty peers array",
                "parse.singbox.unsupported-protocol-variant",
            )
        interface_ip, interface_ipv6 = _parse_addresses(data)
        mtu = _optional_int(data, "mtu")
        if mtu is not None and not 0 <= mtu <= _ROUTING_MARK_MAX:
            raise SingBoxCodecError(
                "mtu",
                f"Sing-box WireGuard mtu must be between 0 and {_ROUTING_MARK_MAX}",
                "parse.singbox.invalid-field",
            )
        return WireguardNode(
            **_common_kwargs(data, udp=True),
            private_key=_optional_string(data, "private_key") or "",
            interface_ip=interface_ip,
            interface_ipv6=interface_ipv6,
            mtu=mtu,
            workers=_optional_int(data, "workers"),
            peers=[_parse_peer(peer, index) for index, peer in enumerate(peers)],
        )

    def _check_protocol(self, node: Node) -> list[str]:
        assert isinstance(node, WireguardNode)
        unsupported = []
        if not isinstance(node.private_key, str) or not node.private_key:
            unsupported.append("private_key")
        if not isinstance(node.peers, list) or not node.peers:
            unsupported.append("peers")
        if node.mtu is not None and (
            type(node.mtu) is not int or not 0 <= node.mtu <= _ROUTING_MARK_MAX
        ):
            unsupported.append("mtu")
        if node.workers is not None and type(node.workers) is not int:
            unsupported.append("workers")
        if _node_addresses(node) is None:
            unsupported.append("address")
        for index, peer in enumerate(
            node.peers if isinstance(node.peers, list) else []
        ):
            if not isinstance(peer, WireguardPeer):
                unsupported.append(f"peers[{index}]")
                continue
            if not isinstance(peer.server, str) or not peer.server:
                unsupported.append(f"peers[{index}].address")
            if type(peer.port) is not int or not 1 <= peer.port <= 65535:
                unsupported.append(f"peers[{index}].port")
            if not isinstance(peer.public_key, str) or not peer.public_key:
                unsupported.append(f"peers[{index}].public_key")
            if (
                not isinstance(peer.allowed_ips, list)
                or not peer.allowed_ips
                or not all(isinstance(value, str) for value in peer.allowed_ips)
            ):
                unsupported.append(f"peers[{index}].allowed_ips")
            if peer.preshared_key is not None and not isinstance(
                peer.preshared_key, str
            ):
                unsupported.append(f"peers[{index}].preshared_key")
            if peer.reserved is not None and (
                not isinstance(peer.reserved, list)
                or any(
                    type(value) is not int or not 0 <= value <= 255
                    for value in peer.reserved
                )
            ):
                unsupported.append(f"peers[{index}].reserved")
        return unsupported

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        assert isinstance(node, WireguardNode)
        addresses = [value for value, _ in (_node_addresses(node) or [])]
        if addresses:
            out["address"] = addresses[0] if len(addresses) == 1 else addresses
        out["private_key"] = node.private_key
        if node.mtu is not None:
            out["mtu"] = node.mtu
        if node.workers is not None:
            out["workers"] = node.workers
        out["peers"] = []
        for peer in node.peers or []:
            encoded: dict[str, Any] = {
                "address": peer.server,
                "port": peer.port,
                "public_key": peer.public_key,
                "allowed_ips": list(peer.allowed_ips),
            }
            if peer.preshared_key:
                encoded["pre_shared_key"] = peer.preshared_key
            if peer.reserved is not None:
                encoded["reserved"] = list(peer.reserved)
            out["peers"].append(encoded)


CODEC = SingBoxWireguardEndpointCodec()
