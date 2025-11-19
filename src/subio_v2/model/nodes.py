from enum import StrEnum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union

class Protocol(StrEnum):
    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    SOCKS5 = "socks5"
    HTTP = "http"
    WIREGUARD = "wireguard"
    HYSTERIA = "hysteria"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    JUICITY = "juicity"

@dataclass
class TLSSettings:
    enabled: bool = False
    server_name: Optional[str] = None  # sni
    alpn: Optional[List[str]] = None
    skip_cert_verify: bool = False
    fingerprint: Optional[str] = None # chrome, firefox, randomize...
    client_fingerprint: Optional[str] = None # utls fingerprint
    reality_opts: Optional[Dict[str, str]] = None # public-key, short-id

class Network(StrEnum):
    TCP = "tcp"
    WS = "ws"
    HTTP = "http"
    H2 = "h2"
    GRPC = "grpc"

@dataclass
class TransportSettings:
    network: Network = Network.TCP
    path: Optional[str] = None # ws/h2/http path
    headers: Optional[Dict[str, str]] = None # ws/http headers
    host: Optional[List[str]] = None # h2 host
    method: Optional[str] = "GET" # http method
    grpc_service_name: Optional[str] = None
    max_early_data: Optional[int] = None
    early_data_header_name: Optional[str] = None

@dataclass
class SmuxSettings:
    enabled: bool = False
    protocol: str = "smux" # smux, yamux, h2mux
    max_connections: int = 4
    min_streams: int = 4
    max_streams: int = 0
    padding: bool = False
    brutal_opts: Optional[Dict[str, Any]] = None

@dataclass
class BaseNode:
    name: str
    type: Protocol
    server: str
    port: int
    udp: bool = True # Default true for most modern proxies
    ip_version: Optional[str] = None # ipv4, ipv6, dual
    tfo: bool = False
    mptcp: bool = False
    
    # Link to other nodes (chains) - store names or references?
    # For v2 initial phase, we might skip complex chains, but let's keep fields.
    dialer_proxy: Optional[str] = None 

@dataclass
class ShadowsocksNode(BaseNode):
    cipher: str = "chacha20-ietf-poly1305"
    password: str = ""
    plugin: Optional[str] = None
    plugin_opts: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.type != Protocol.SHADOWSOCKS:
            self.type = Protocol.SHADOWSOCKS

@dataclass
class VmessNode(BaseNode):
    uuid: str = ""
    alter_id: int = 0
    cipher: str = "auto"
    global_padding: bool = False
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)
    packet_encoding: Optional[str] = None

    def __post_init__(self):
        if self.type != Protocol.VMESS:
            self.type = Protocol.VMESS

@dataclass
class VlessNode(BaseNode):
    uuid: str = ""
    flow: Optional[str] = None # xtls-rprx-vision
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)
    packet_encoding: Optional[str] = None

    def __post_init__(self):
        if self.type != Protocol.VLESS:
            self.type = Protocol.VLESS

@dataclass
class TrojanNode(BaseNode):
    password: str = ""
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)
    
    def __post_init__(self):
        if self.type != Protocol.TROJAN:
            self.type = Protocol.TROJAN

@dataclass
class Socks5Node(BaseNode):
    username: Optional[str] = None
    password: Optional[str] = None
    tls: TLSSettings = field(default_factory=TLSSettings) # Some variants support TLS
    
    def __post_init__(self):
        if self.type != Protocol.SOCKS5:
            self.type = Protocol.SOCKS5

@dataclass
class HttpNode(BaseNode):
    username: Optional[str] = None
    password: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    tls: TLSSettings = field(default_factory=TLSSettings)
    
    def __post_init__(self):
        if self.type != Protocol.HTTP:
            self.type = Protocol.HTTP

@dataclass
class WireguardNode(BaseNode):
    private_key: str = ""
    public_key: str = ""
    preshared_key: Optional[str] = None
    endpoint: Optional[str] = None # Usually same as server:port, but can be separate
    allowed_ips: List[str] = field(default_factory=lambda: ["0.0.0.0/0", "::/0"])
    reserved: Optional[List[int]] = None
    mtu: Optional[int] = None
    
    def __post_init__(self):
        if self.type != Protocol.WIREGUARD:
            self.type = Protocol.WIREGUARD

Node = Union[
    ShadowsocksNode, 
    VmessNode, 
    VlessNode, 
    TrojanNode, 
    Socks5Node, 
    HttpNode, 
    WireguardNode
]

