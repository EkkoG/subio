from __future__ import annotations

from dataclasses import fields
from ipaddress import ip_interface
from typing import Any

from subio_v2.adapters.singbox.outbound import (
    SingBoxCodecError,
    _ROUTING_MARK_MAX,
    _optional_bool,
    _optional_int,
    _optional_string,
)
from subio_v2.core.nodes import (
    BaseNode,
    Node,
    Protocol,
    TailscaleNode,
    WireguardNode,
    WireguardPeer,
)
from subio_v2.core.results import IssueDraft, IssueSeverity

_COMMON_KEYS = frozenset(
    {
        "type",
        "tag",
        "detour",
        "bind_interface",
        "routing_mark",
        "tcp_fast_open",
        "tcp_multi_path",
    }
)
_COMMON_NODE_FIELDS = frozenset(
    {
        "name",
        "type",
        "udp",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "interface_name",
        "routing_mark",
        "record",
    }
)
_WIREGUARD_KEYS = _COMMON_KEYS | frozenset(
    {"address", "private_key", "peers", "mtu", "workers"}
)
_TAILSCALE_KEYS = _COMMON_KEYS | frozenset(
    {
        "auth_key",
        "control_url",
        "ephemeral",
        "hostname",
        "accept_routes",
        "exit_node",
        "exit_node_allow_lan_access",
    }
)
_WIREGUARD_PEER_KEYS = frozenset(
    {"address", "port", "public_key", "pre_shared_key", "allowed_ips", "reserved"}
)


def _required_tag(data: dict[str, Any]) -> str:
    tag = data.get("tag")
    if not isinstance(tag, str) or not tag:
        raise SingBoxCodecError(
            "tag",
            "Sing-box endpoint field 'tag' must be a non-empty string",
            "parse.singbox.invalid-field",
        )
    return tag


def _common_kwargs(data: dict[str, Any], *, udp: bool) -> dict[str, Any]:
    routing_mark = data.get("routing_mark")
    if routing_mark is not None and type(routing_mark) is not int:
        raise SingBoxCodecError(
            "routing_mark",
            "String routing marks are not supported",
            "parse.singbox.unsupported-field",
        )
    if routing_mark is not None and not 0 <= routing_mark <= _ROUTING_MARK_MAX:
        raise SingBoxCodecError(
            "routing_mark",
            f"Sing-box field 'routing_mark' must be between 0 and {_ROUTING_MARK_MAX}",
            "parse.singbox.invalid-field",
        )
    return {
        "name": _required_tag(data),
        "server": None,
        "port": None,
        "udp": udp,
        "dialer_proxy": _optional_string(data, "detour"),
        "interface_name": _optional_string(data, "bind_interface"),
        "routing_mark": routing_mark,
        "tfo": _optional_bool(data, "tcp_fast_open"),
        "mptcp": _optional_bool(data, "tcp_multi_path"),
    }


def _string_or_list(data: dict[str, Any], key: str) -> list[str] | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise SingBoxCodecError(
        key,
        f"Sing-box field '{key}' must be a string or string array",
        "parse.singbox.invalid-field",
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


def _emit_common(out: dict[str, Any], node: BaseNode) -> None:
    if node.dialer_proxy:
        out["detour"] = node.dialer_proxy
    if node.interface_name:
        out["bind_interface"] = node.interface_name
    if node.routing_mark is not None:
        out["routing_mark"] = node.routing_mark
    if node.tfo:
        out["tcp_fast_open"] = True
    if node.mptcp:
        out["tcp_multi_path"] = True


class SingBoxEndpointCodec:
    singbox_type: str
    protocol: Protocol
    node_class: type[BaseNode]
    allowed_keys: frozenset[str]
    allowed_node_fields: frozenset[str]
    expected_udp: bool

    @property
    def target_constraints(self) -> dict[str, object]:
        return {}

    def check(self, node: Node) -> list[IssueDraft]:
        if not isinstance(node, self.node_class):
            return [
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Expected {self.node_class.__name__}, got {type(node).__name__}",
                    "type",
                )
            ]
        default = self.node_class(name="__singbox_default__")
        unsupported = [
            item.name
            for item in fields(node)
            if item.name not in self.allowed_node_fields
            and getattr(node, item.name) != getattr(default, item.name)
        ]
        if not isinstance(node.name, str) or not node.name:
            unsupported.append("name")
        for field in ("dialer_proxy", "interface_name"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                unsupported.append(field)
        for field in ("tfo", "mptcp"):
            if type(getattr(node, field)) is not bool:
                unsupported.append(field)
        if node.udp is not self.expected_udp:
            unsupported.append("udp")
        if node.routing_mark is not None and (
            type(node.routing_mark) is not int
            or not 0 <= node.routing_mark <= _ROUTING_MARK_MAX
        ):
            unsupported.append("routing_mark")
        unsupported.extend(self._check_protocol(node))
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Node field cannot be represented by sing-box endpoint: {field}",
                field,
                code="conversion.unsupported-platform-field",
            )
            for field in sorted(set(unsupported))
        ]

    def _check_protocol(self, node: Node) -> list[str]:
        return []

    def encode(self, node: Node) -> dict[str, Any]:
        issues = self.check(node)
        if issues:
            issue = issues[0]
            raise SingBoxCodecError(issue.field or "node", issue.message, issue.code)
        out: dict[str, Any] = {"type": self.singbox_type, "tag": node.name}
        _emit_common(out, node)
        self._emit_protocol(out, node)
        return out

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        raise NotImplementedError


class SingBoxWireguardEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "wireguard"
    protocol = Protocol.WIREGUARD
    node_class = WireguardNode
    allowed_keys = _WIREGUARD_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {"private_key", "interface_ip", "interface_ipv6", "mtu", "workers", "peers"}
    )
    expected_udp = True

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


class SingBoxTailscaleEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "tailscale"
    protocol = Protocol.TAILSCALE
    node_class = TailscaleNode
    allowed_keys = _TAILSCALE_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {
            "hostname",
            "auth_key",
            "control_url",
            "ephemeral",
            "accept_routes",
            "exit_node",
            "exit_node_allow_lan_access",
        }
    )
    expected_udp = False

    def parse(self, data: dict[str, Any]) -> TailscaleNode:
        auth_key = _optional_string(data, "auth_key")
        if not auth_key:
            raise SingBoxCodecError(
                "auth_key",
                "Sing-box Tailscale endpoint requires auth_key without local state",
                "parse.singbox.unsupported-protocol-variant",
            )
        exit_node = _optional_string(data, "exit_node")
        if exit_node in {"auto", "auto:any", "none"}:
            raise SingBoxCodecError(
                "exit_node",
                f"Sing-box Tailscale exit_node selector '{exit_node}' is not portable",
                "parse.singbox.unsupported-protocol-variant",
            )
        return TailscaleNode(
            **_common_kwargs(data, udp=False),
            auth_key=auth_key,
            control_url=_optional_string(data, "control_url"),
            ephemeral=_optional_bool(data, "ephemeral"),
            hostname=_optional_string(data, "hostname"),
            accept_routes=_optional_bool(data, "accept_routes"),
            exit_node=exit_node,
            exit_node_allow_lan_access=_optional_bool(
                data, "exit_node_allow_lan_access"
            ),
        )

    def _check_protocol(self, node: Node) -> list[str]:
        assert isinstance(node, TailscaleNode)
        unsupported = []
        if not isinstance(node.auth_key, str) or not node.auth_key:
            unsupported.append("auth_key")
        for field in ("control_url", "hostname", "exit_node"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                unsupported.append(field)
        if isinstance(node.exit_node, str) and node.exit_node in {
            "auto",
            "auto:any",
            "none",
        }:
            unsupported.append("exit_node")
        for field in ("ephemeral", "accept_routes", "exit_node_allow_lan_access"):
            if type(getattr(node, field)) is not bool:
                unsupported.append(field)
        return unsupported

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        assert isinstance(node, TailscaleNode)
        out["auth_key"] = node.auth_key
        if node.control_url:
            out["control_url"] = node.control_url
        out["ephemeral"] = node.ephemeral
        if node.hostname:
            out["hostname"] = node.hostname
        out["accept_routes"] = node.accept_routes
        if node.exit_node:
            out["exit_node"] = node.exit_node
        out["exit_node_allow_lan_access"] = node.exit_node_allow_lan_access


_CODECS = (SingBoxWireguardEndpointCodec(), SingBoxTailscaleEndpointCodec())

SINGBOX_ENDPOINT_CODECS = {codec.protocol: codec for codec in _CODECS}
SINGBOX_ENDPOINT_CODECS_BY_TYPE = {codec.singbox_type: codec for codec in _CODECS}


def encode_endpoint(node: Node) -> dict[str, Any]:
    codec = SINGBOX_ENDPOINT_CODECS.get(node.type)
    if codec is None:
        raise SingBoxCodecError(
            "type",
            f"Protocol '{node.type.value}' is not supported as a sing-box endpoint",
            "conversion.unsupported-protocol",
        )
    return codec.encode(node)
