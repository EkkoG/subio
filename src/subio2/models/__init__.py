"""Data models for SubIO2."""
# Use composite pattern for better extensibility
from .node_composite import (
    CompositeNode as Node,
    NodeType,
    # Protocol configurations
    ProtocolConfig,
    ShadowsocksProtocol,
    VmessProtocol,
    TrojanProtocol,
    VlessProtocol,
    HysteriaProtocol,
    Hysteria2Protocol,
    HttpProtocol,
    Socks5Protocol,
    # Components
    BasicAuth,
    TLSConfig,
    Transport,
    WebSocketTransport,
    GRPCTransport
)
from .config import Config, Provider, Artifact, Ruleset, UploaderConfig

__all__ = [
    "Node", "NodeType", "ProtocolConfig",
    "ShadowsocksProtocol", "VmessProtocol", "TrojanProtocol", "VlessProtocol",
    "HysteriaProtocol", "Hysteria2Protocol", "HttpProtocol", "Socks5Protocol",
    "BasicAuth", "TLSConfig", "Transport", "WebSocketTransport", "GRPCTransport",
    "Config", "Provider", "Artifact", "Ruleset", "UploaderConfig"
]