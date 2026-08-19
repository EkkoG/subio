from __future__ import annotations

from dataclasses import dataclass

from subio_v2.model.nodes import (
    AnyTLSNode,
    BaseNode,
    DirectNode,
    DNSNode,
    GostRelayNode,
    HttpNode,
    Hysteria2Node,
    HysteriaNode,
    JuicityNode,
    MasqueNode,
    MieruNode,
    OpenVPNNode,
    Protocol,
    RejectNode,
    RematchNode,
    ShadowQUICNode,
    ShadowsocksNode,
    ShadowsocksRNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    SudokuNode,
    TailscaleNode,
    TrojanNode,
    TrustTunnelNode,
    TUICNode,
    VlessNode,
    VmessNode,
    WireguardNode,
)


@dataclass(frozen=True)
class ProtocolDefinition:
    protocol: Protocol
    node_class: type[BaseNode]
    requires_endpoint: bool = True
    user_override_fields: frozenset[str] = frozenset()


_RUNTIME_USER_OVERRIDE_FIELDS: dict[Protocol, frozenset[str]] = {
    Protocol.ANYTLS: frozenset({"server", "port", "password"}),
    Protocol.DIRECT: frozenset({"server", "port"}),
    Protocol.DNS: frozenset({"server", "port"}),
    Protocol.GOST_RELAY: frozenset({"server", "port", "username", "password"}),
    Protocol.HTTP: frozenset({"server", "port", "username", "password"}),
    Protocol.HYSTERIA: frozenset({"server", "port", "auth", "auth_str"}),
    Protocol.HYSTERIA2: frozenset(
        {"server", "port", "password", "obfs_password"}
    ),
    Protocol.JUICITY: frozenset({"server", "port", "uuid", "password"}),
    Protocol.MASQUE: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "public_key",
        }
    ),
    Protocol.MIERU: frozenset({"server", "port", "username", "password"}),
    Protocol.OPENVPN: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "auth",
            "cipher",
            "private_key",
        }
    ),
    Protocol.REJECT: frozenset({"server", "port"}),
    Protocol.REMATCH: frozenset({"server", "port"}),
    Protocol.SHADOWQUIC: frozenset({"server", "port", "username", "password"}),
    Protocol.SHADOWSOCKS: frozenset({"server", "port", "cipher", "password"}),
    Protocol.SHADOWSOCKSR: frozenset({"server", "port", "cipher", "password"}),
    Protocol.SNELL: frozenset({"server", "port", "psk"}),
    Protocol.SOCKS5: frozenset({"server", "port", "username", "password"}),
    Protocol.SSH: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "private_key_passphrase",
        }
    ),
    Protocol.SUDOKU: frozenset({"server", "port"}),
    Protocol.TAILSCALE: frozenset({"server", "port", "auth_key"}),
    Protocol.TROJAN: frozenset({"server", "port", "password"}),
    Protocol.TRUSTTUNNEL: frozenset(
        {"server", "port", "username", "password"}
    ),
    Protocol.TUIC: frozenset({"server", "port", "token", "uuid", "password"}),
    Protocol.VLESS: frozenset({"server", "port", "uuid"}),
    Protocol.VMESS: frozenset({"server", "port", "uuid", "alter_id", "cipher"}),
    Protocol.WIREGUARD: frozenset(
        {"server", "port", "private_key", "public_key", "preshared_key"}
    ),
}


def _definition(
    protocol: Protocol,
    node_class: type[BaseNode],
    *,
    requires_endpoint: bool = True,
) -> ProtocolDefinition:
    return ProtocolDefinition(
        protocol=protocol,
        node_class=node_class,
        requires_endpoint=requires_endpoint,
        user_override_fields=_RUNTIME_USER_OVERRIDE_FIELDS[protocol],
    )


_DEFINITIONS = (
    _definition(Protocol.SHADOWSOCKS, ShadowsocksNode),
    _definition(Protocol.SHADOWSOCKSR, ShadowsocksRNode),
    _definition(Protocol.VMESS, VmessNode),
    _definition(Protocol.VLESS, VlessNode),
    _definition(Protocol.TROJAN, TrojanNode),
    _definition(Protocol.SOCKS5, Socks5Node),
    _definition(Protocol.HTTP, HttpNode),
    _definition(Protocol.WIREGUARD, WireguardNode),
    _definition(Protocol.TAILSCALE, TailscaleNode, requires_endpoint=False),
    _definition(Protocol.MASQUE, MasqueNode),
    _definition(Protocol.TRUSTTUNNEL, TrustTunnelNode),
    _definition(Protocol.DIRECT, DirectNode, requires_endpoint=False),
    _definition(Protocol.DNS, DNSNode, requires_endpoint=False),
    _definition(Protocol.REMATCH, RematchNode, requires_endpoint=False),
    _definition(Protocol.GOST_RELAY, GostRelayNode),
    _definition(Protocol.SHADOWQUIC, ShadowQUICNode),
    _definition(Protocol.OPENVPN, OpenVPNNode),
    _definition(Protocol.SUDOKU, SudokuNode),
    _definition(Protocol.REJECT, RejectNode, requires_endpoint=False),
    _definition(Protocol.ANYTLS, AnyTLSNode),
    _definition(Protocol.HYSTERIA, HysteriaNode),
    _definition(Protocol.HYSTERIA2, Hysteria2Node),
    _definition(Protocol.SSH, SSHNode),
    _definition(Protocol.SNELL, SnellNode),
    _definition(Protocol.MIERU, MieruNode, requires_endpoint=False),
    _definition(Protocol.JUICITY, JuicityNode),
    _definition(Protocol.TUIC, TUICNode),
)

_BY_PROTOCOL = {definition.protocol: definition for definition in _DEFINITIONS}
if len(_BY_PROTOCOL) != len(_DEFINITIONS):
    raise ValueError("Protocol definitions must use unique protocol IDs")


def get_definition(protocol: Protocol) -> ProtocolDefinition | None:
    return _BY_PROTOCOL.get(protocol)


def all_definitions() -> tuple[ProtocolDefinition, ...]:
    return _DEFINITIONS
