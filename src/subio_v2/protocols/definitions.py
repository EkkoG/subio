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


_DEFINITIONS = (
    ProtocolDefinition(Protocol.SHADOWSOCKS, ShadowsocksNode),
    ProtocolDefinition(Protocol.SHADOWSOCKSR, ShadowsocksRNode),
    ProtocolDefinition(Protocol.VMESS, VmessNode),
    ProtocolDefinition(Protocol.VLESS, VlessNode),
    ProtocolDefinition(Protocol.TROJAN, TrojanNode),
    ProtocolDefinition(Protocol.SOCKS5, Socks5Node),
    ProtocolDefinition(Protocol.HTTP, HttpNode),
    ProtocolDefinition(Protocol.WIREGUARD, WireguardNode),
    ProtocolDefinition(Protocol.TAILSCALE, TailscaleNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.MASQUE, MasqueNode),
    ProtocolDefinition(Protocol.TRUSTTUNNEL, TrustTunnelNode),
    ProtocolDefinition(Protocol.DIRECT, DirectNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.DNS, DNSNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.REMATCH, RematchNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.GOST_RELAY, GostRelayNode),
    ProtocolDefinition(Protocol.SHADOWQUIC, ShadowQUICNode),
    ProtocolDefinition(Protocol.OPENVPN, OpenVPNNode),
    ProtocolDefinition(Protocol.SUDOKU, SudokuNode),
    ProtocolDefinition(Protocol.REJECT, RejectNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.ANYTLS, AnyTLSNode),
    ProtocolDefinition(Protocol.HYSTERIA, HysteriaNode),
    ProtocolDefinition(Protocol.HYSTERIA2, Hysteria2Node),
    ProtocolDefinition(Protocol.SSH, SSHNode),
    ProtocolDefinition(Protocol.SNELL, SnellNode),
    ProtocolDefinition(Protocol.MIERU, MieruNode, requires_endpoint=False),
    ProtocolDefinition(Protocol.JUICITY, JuicityNode),
    ProtocolDefinition(Protocol.TUIC, TUICNode),
)

_BY_PROTOCOL = {definition.protocol: definition for definition in _DEFINITIONS}
if len(_BY_PROTOCOL) != len(_DEFINITIONS):
    raise ValueError("Protocol definitions must use unique protocol IDs")


def get_definition(protocol: Protocol) -> ProtocolDefinition | None:
    return _BY_PROTOCOL.get(protocol)


def all_definitions() -> tuple[ProtocolDefinition, ...]:
    return _DEFINITIONS
