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
    ANYTLS = "anytls"
    SSH = "ssh"
    SNELL = "snell"


@dataclass
class TLSSettings:
    enabled: bool = False
    server_name: Optional[str] = None  # sni
    alpn: Optional[List[str]] = None
    skip_cert_verify: bool = False
    fingerprint: Optional[str] = None  # chrome, firefox, randomize...
    client_fingerprint: Optional[str] = None  # utls fingerprint
    reality_opts: Optional[Dict[str, str]] = None  # public-key, short-id
    ech_opts: Optional[Dict[str, Any]] = None  # Hysteria2 ECH
    certificate: Optional[str] = None  # mTLS
    private_key: Optional[str] = None  # mTLS


class Network(StrEnum):
    TCP = "tcp"
    WS = "ws"
    HTTP = "http"
    H2 = "h2"
    GRPC = "grpc"


@dataclass
class TransportSettings:
    network: Network = Network.TCP
    path: Optional[str] = None  # ws/h2/http path
    headers: Optional[Dict[str, str]] = None  # ws/http headers
    host: Optional[List[str]] = None  # h2 host
    method: Optional[str] = "GET"  # http method
    grpc_service_name: Optional[str] = None
    max_early_data: Optional[int] = None
    early_data_header_name: Optional[str] = None


@dataclass
class SmuxSettings:
    enabled: bool = False
    protocol: str = "smux"  # smux, yamux, h2mux
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
    udp: bool = True  # Default true for most modern proxies
    ip_version: Optional[str] = None  # ipv4, ipv6, dual
    tfo: bool = False
    mptcp: bool = False
    dialer_proxy: Optional[str] = None
    # Multi-user support: maps username to credential overrides
    # e.g., {"lisa": {"password": "xxx"}, "vita": {"password": "yyy"}}
    users: Optional[Dict[str, Dict[str, Any]]] = None
    # Original name before any rename processing (for filtering)
    original_name: Optional[str] = None


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
    vmess_aead: bool = False  # Surge-specific: vmess-aead parameter
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
    flow: Optional[str] = None  # xtls-rprx-vision
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
    tls: TLSSettings = field(default_factory=TLSSettings)

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
    endpoint: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=lambda: ["0.0.0.0/0", "::/0"])
    reserved: Optional[List[int]] = None
    mtu: Optional[int] = None

    def __post_init__(self):
        if self.type != Protocol.WIREGUARD:
            self.type = Protocol.WIREGUARD


@dataclass
class AnyTLSNode(BaseNode):
    password: str = ""
    tls: TLSSettings = field(default_factory=TLSSettings)
    idle_session_check_interval: Optional[int] = None
    idle_session_timeout: Optional[int] = None
    min_idle_session: Optional[int] = None

    def __post_init__(self):
        if self.type != Protocol.ANYTLS:
            self.type = Protocol.ANYTLS


@dataclass
class Hysteria2Node(BaseNode):
    password: str = ""
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    up: Optional[str] = None
    down: Optional[str] = None
    obfs: Optional[str] = None
    obfs_password: Optional[str] = None
    tls: TLSSettings = field(default_factory=TLSSettings)

    def __post_init__(self):
        if self.type != Protocol.HYSTERIA2:
            self.type = Protocol.HYSTERIA2


@dataclass
class SSHNode(BaseNode):
    username: str = ""
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    keystore_id: Optional[str] = None  # Reference to Keystore entry ID
    host_key: Optional[List[str]] = None
    host_key_algorithms: Optional[List[str]] = None

    def __post_init__(self):
        if self.type != Protocol.SSH:
            self.type = Protocol.SSH


@dataclass
class SnellNode(BaseNode):
    psk: str = ""
    version: Optional[int] = None
    obfs: Optional[str] = None  # http, tls
    obfs_host: Optional[str] = None
    tls: TLSSettings = field(default_factory=TLSSettings)

    def __post_init__(self):
        if self.type != Protocol.SNELL:
            self.type = Protocol.SNELL


@dataclass
class TUICNode(BaseNode):
    token: Optional[str] = None  # TUIC v4 uses token
    password: Optional[str] = None  # TUIC v5 uses password
    uuid: Optional[str] = None  # TUIC v5 uses uuid
    version: Optional[int] = None  # 4 or 5
    tls: TLSSettings = field(default_factory=TLSSettings)

    def __post_init__(self):
        if self.type != Protocol.TUIC:
            self.type = Protocol.TUIC


Node = Union[
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    WireguardNode,
    AnyTLSNode,
    Hysteria2Node,
    SSHNode,
    SnellNode,
    TUICNode,
]


def clone_node_for_user(node: Node, username: str) -> Node | None:
    """
    Clone a node and apply user-specific credential overrides.
    Returns None if the node doesn't have the specified user.
    """
    if not node.users or username not in node.users:
        return None

    import copy

    new_node = copy.deepcopy(node)
    user_overrides = node.users[username]

    # Apply overrides to the node
    for key, value in user_overrides.items():
        if hasattr(new_node, key):
            setattr(new_node, key, value)

    # Clear users field in the cloned node (no longer needed)
    new_node.users = None

    return new_node


def get_nodes_for_user(nodes: List[Node], username: str) -> List[Node]:
    """
    Process a list of nodes for a specific user.
    - Nodes with users config: clone with user-specific credentials
    - Nodes without users config: include as-is (shared nodes)
    """
    result = []
    for node in nodes:
        if node.users:
            # Multi-user node: clone for specific user
            if username in node.users:
                user_node = clone_node_for_user(node, username)
                if user_node:
                    result.append(user_node)
            # If user not in this node's users, skip it
        else:
            # Regular node: include as-is
            import copy

            result.append(copy.deepcopy(node))
    return result
