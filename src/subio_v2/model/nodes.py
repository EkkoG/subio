from enum import StrEnum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union

from subio_v2.dialect import DialectContext


class Protocol(StrEnum):
    SHADOWSOCKS = "shadowsocks"
    SHADOWSOCKSR = "shadowsocksr"
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
    MIERU = "mieru"
    SUDOKU = "sudoku"
    MASQUE = "masque"
    TRUSTTUNNEL = "trusttunnel"
    OPENVPN = "openvpn"
    TAILSCALE = "tailscale"
    DIRECT = "direct"
    REJECT = "reject"
    EXTERNAL = "external"
    DNS = "dns"
    CLASH_UNKNOWN = "clash-unknown"


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
    sni_disabled: bool = False
    verify_name: Optional[str] = None
    certificate_sha256: Optional[str] = None
    client_cert_ref: Optional[str] = None


@dataclass
class ShadowTLSSettings:
    password: Optional[str] = field(default=None, repr=False)
    server_name: Optional[str] = None
    version: int = 2

    @property
    def enabled(self) -> bool:
        return bool(self.password)


@dataclass
class SurgePolicyOptions:
    allow_other_interface: Optional[bool] = None
    dns_follow_interface: Optional[bool] = None
    no_error_alert: Optional[bool] = None
    hybrid: Optional[str] = None
    tos: Optional[str] = None
    ecn: Optional[str] = None
    block_quic: Optional[str] = None
    test_url: Optional[str] = None
    test_timeout: Optional[int] = None
    test_udp: Optional[str] = None


class Network(StrEnum):
    TCP = "tcp"
    WS = "ws"
    HTTP = "http"
    H2 = "h2"
    GRPC = "grpc"
    XHTTP = "xhttp"


class HttpVariant(StrEnum):
    AUTO = "auto"
    HTTP = "http"
    HTTPS = "https"
    H2_CONNECT = "h2-connect"


class MasqueMode(StrEnum):
    FORWARD_PROXY = "forward-proxy"
    CONNECT_IP = "connect-ip"
    H3_L4_PROXY = "h3-l4proxy"


class RejectMode(StrEnum):
    REJECT = "reject"
    DROP = "reject-drop"
    NO_DROP = "reject-no-drop"
    TINYGIF = "reject-tinygif"


@dataclass
class TransportSettings:
    network: Union[Network, str] = Network.TCP
    path: Optional[Union[str, List[str]]] = None  # ws/h2/http path
    headers: Optional[Dict[str, Any]] = None  # ws/http headers
    host: Optional[List[str]] = None  # h2 host
    method: Optional[str] = "GET"  # http method
    grpc_service_name: Optional[str] = None
    max_early_data: Optional[int] = None
    early_data_header_name: Optional[str] = None
    # Unmapped nested transport fields, keyed by Clash option block (e.g. ws-opts).
    extra: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    extra_context: Optional[DialectContext] = field(
        default=None, repr=False, compare=False
    )

    @property
    def network_value(self) -> str:
        return self.network.value if isinstance(self.network, Network) else self.network


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
    # Some native proxy policies (for example Surge Tailscale and DIRECT aliases)
    # have no remote endpoint. Concrete protocol validation decides whether these
    # fields are required.
    server: Optional[Union[str, List[str]]] = None
    port: Optional[int] = None
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
    interface_name: Optional[str] = None
    routing_mark: Optional[int] = None
    # Unmapped Clash fields preserved for round-trip emit
    extra: Dict[str, Any] = field(default_factory=dict)
    extra_context: Optional[DialectContext] = field(
        default=None, repr=False, compare=False
    )
    surge_options: SurgePolicyOptions = field(default_factory=SurgePolicyOptions)
    shadow_tls: ShadowTLSSettings = field(default_factory=ShadowTLSSettings)
    source_extensions: Dict[str, Any] = field(default_factory=dict, repr=False)
    # Workflow provenance for structured conversion issues; never emitted.
    source_provider: Optional[str] = field(default=None, repr=False, compare=False)
    source_context: Optional[DialectContext] = field(
        default=None, repr=False, compare=False
    )


@dataclass
class ShadowsocksNode(BaseNode):
    cipher: str = "chacha20-ietf-poly1305"
    password: str = field(default="", repr=False)
    udp_port: Optional[int] = None
    plugin: Optional[str] = None
    plugin_opts: Optional[Dict[str, Any]] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.SHADOWSOCKS:
            self.type = Protocol.SHADOWSOCKS


@dataclass
class ShadowsocksRNode(BaseNode):
    cipher: str = ""
    password: str = ""
    obfs: str = ""
    ssr_protocol: str = ""
    obfs_param: Optional[str] = None
    protocol_param: Optional[str] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.SHADOWSOCKSR:
            self.type = Protocol.SHADOWSOCKSR


@dataclass
class VmessNode(BaseNode):
    uuid: str = field(default="", repr=False)
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
    uuid: str = field(default="", repr=False)
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
    password: str = field(default="", repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.TROJAN:
            self.type = Protocol.TROJAN


@dataclass
class Socks5Node(BaseNode):
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)

    def __post_init__(self):
        if self.type != Protocol.SOCKS5:
            self.type = Protocol.SOCKS5


@dataclass
class HttpNode(BaseNode):
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    headers: Optional[Dict[str, str]] = None
    variant: HttpVariant = HttpVariant.AUTO
    max_streams: Optional[int] = None
    tls: TLSSettings = field(default_factory=TLSSettings)

    def __post_init__(self):
        if self.type != Protocol.HTTP:
            self.type = Protocol.HTTP


@dataclass
class WireguardNode(BaseNode):
    private_key: str = field(default="", repr=False)
    public_key: str = ""
    preshared_key: Optional[str] = None
    pre_shared_key: Optional[str] = None  # clash: pre-shared-key on peer
    interface_ip: Optional[Any] = None  # clash: ip
    interface_ipv6: Optional[Any] = None  # clash: ipv6
    allowed_ips: Optional[List[str]] = None
    reserved: Optional[List[int]] = None
    mtu: Optional[int] = None
    workers: Optional[int] = None
    persistent_keepalive: Optional[int] = None
    amnezia_wg_option: Optional[Dict[str, Any]] = None
    peers: Optional[List[Dict[str, Any]]] = None
    remote_dns_resolve: Optional[bool] = None
    dns_servers: Optional[List[str]] = None
    refresh_server_ip_interval: Optional[int] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.WIREGUARD:
            self.type = Protocol.WIREGUARD


@dataclass
class TailscaleNode(BaseNode):
    hostname: Optional[str] = None
    auth_key: Optional[str] = field(default=None, repr=False)
    interactive_login: bool = False
    control_url: Optional[str] = None
    state_dir: Optional[str] = None
    ephemeral: bool = False
    accept_routes: bool = False
    exit_node: Optional[str] = None
    exit_node_allow_lan_access: bool = False
    derp_only: bool = False
    auto_add_magic_dns_rule: Optional[bool] = None
    idle_keepalive: Optional[int] = None
    prefer_ipv6: bool = False
    dns_servers: Optional[List[str]] = None
    mtu: Optional[int] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.TAILSCALE:
            self.type = Protocol.TAILSCALE


@dataclass
class MasqueNode(BaseNode):
    mode: MasqueMode = MasqueMode.FORWARD_PROXY
    transport: str = "h3"
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    private_key: Optional[str] = field(default=None, repr=False)
    public_key: Optional[str] = None
    interface_ip: Optional[str] = None
    interface_ipv6: Optional[str] = None
    mtu: Optional[int] = None
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    remote_dns_resolve: bool = False
    dns_servers: Optional[List[str]] = None
    congestion_controller: Optional[str] = None
    cwnd: Optional[int] = None
    bbr_profile: Optional[str] = None
    handshake_timeout: Optional[int] = None
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.MASQUE:
            self.type = Protocol.MASQUE


@dataclass
class TrustTunnelNode(BaseNode):
    username: str = ""
    password: str = field(default="", repr=False)
    headers: Optional[str] = None
    max_streams: Optional[int] = None
    quic: bool = False
    websocket: bool = False
    health_check: Optional[bool] = None
    congestion_controller: Optional[str] = None
    cwnd: Optional[int] = None
    bbr_profile: Optional[str] = None
    max_connections: Optional[int] = None
    min_streams: Optional[int] = None
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.TRUSTTUNNEL:
            self.type = Protocol.TRUSTTUNNEL


@dataclass
class DirectNode(BaseNode):
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.DIRECT:
            self.type = Protocol.DIRECT


@dataclass
class RejectNode(BaseNode):
    mode: RejectMode = RejectMode.REJECT

    def __post_init__(self):
        if self.type != Protocol.REJECT:
            self.type = Protocol.REJECT
        if not isinstance(self.mode, RejectMode):
            self.mode = RejectMode(self.mode)


@dataclass
class AnyTLSNode(BaseNode):
    password: str = field(default="", repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)
    reuse: bool = True
    idle_session_check_interval: Optional[int] = None
    idle_session_timeout: Optional[int] = None
    min_idle_session: Optional[int] = None

    def __post_init__(self):
        if self.type != Protocol.ANYTLS:
            self.type = Protocol.ANYTLS


@dataclass
class HysteriaNode(BaseNode):
    ports: Optional[str] = None
    hysteria_protocol: Optional[str] = None
    obfs_protocol: Optional[str] = None
    up: Optional[str] = None
    down: Optional[str] = None
    up_speed: Optional[int] = None
    down_speed: Optional[int] = None
    auth_str: Optional[str] = None
    auth: Optional[str] = None
    obfs: Optional[str] = None
    hop_interval: Optional[int] = None
    tls: TLSSettings = field(default_factory=TLSSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.HYSTERIA:
            self.type = Protocol.HYSTERIA


@dataclass
class Hysteria2Node(BaseNode):
    password: str = field(default="", repr=False)
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    up: Optional[str] = None
    down: Optional[str] = None
    obfs: Optional[str] = None
    obfs_password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.HYSTERIA2:
            self.type = Protocol.HYSTERIA2


@dataclass
class SSHNode(BaseNode):
    username: str = ""
    password: Optional[str] = field(default=None, repr=False)
    private_key: Optional[str] = field(default=None, repr=False)
    private_key_passphrase: Optional[str] = field(default=None, repr=False)
    keystore_id: Optional[str] = None  # Reference to Keystore entry ID
    host_key: Optional[List[str]] = None
    host_key_algorithms: Optional[List[str]] = None
    idle_timeout: Optional[int] = None
    server_fingerprints: Optional[List[str]] = None

    def __post_init__(self):
        if self.type != Protocol.SSH:
            self.type = Protocol.SSH


@dataclass
class SnellNode(BaseNode):
    psk: str = field(default="", repr=False)
    version: Optional[int] = None
    reuse: Optional[bool] = None
    udp_port: Optional[int] = None
    mode: Optional[str] = None
    obfs: Optional[str] = None  # http, tls (legacy)
    obfs_host: Optional[str] = None
    obfs_opts: Optional[Dict[str, Any]] = None
    tls: TLSSettings = field(default_factory=TLSSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.SNELL:
            self.type = Protocol.SNELL


@dataclass
class TUICNode(BaseNode):
    token: Optional[str] = field(default=None, repr=False)  # TUIC v4 uses token
    password: Optional[str] = field(default=None, repr=False)  # TUIC v5 password
    uuid: Optional[str] = field(default=None, repr=False)  # TUIC v5 uses uuid
    version: Optional[int] = None  # 4 or 5
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    tls: TLSSettings = field(default_factory=TLSSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.type != Protocol.TUIC:
            self.type = Protocol.TUIC


@dataclass
class ClashPassthroughNode(BaseNode):
    """Clash Meta-only proxy; full YAML fields kept in `raw` for round-trip."""

    raw: Dict[str, Any] = field(default_factory=dict)
    clash_type: Optional[str] = None


@dataclass
class NativeNode(BaseNode):
    """Source-format proxy record kept losslessly for same-format conversion."""

    native_format: str = ""
    raw: Any = field(default=None, repr=False)
    unsafe: bool = False


Node = Union[
    ShadowsocksNode,
    ShadowsocksRNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    WireguardNode,
    TailscaleNode,
    MasqueNode,
    TrustTunnelNode,
    DirectNode,
    RejectNode,
    AnyTLSNode,
    HysteriaNode,
    Hysteria2Node,
    SSHNode,
    SnellNode,
    TUICNode,
    ClashPassthroughNode,
    NativeNode,
]


_USER_OVERRIDE_FIELDS = frozenset(
    {
        "server",
        "port",
        "username",
        "password",
        "uuid",
        "cipher",
        "alter_id",
        "token",
        "auth",
        "auth_str",
        "auth_key",
        "psk",
        "private_key",
        "private_key_passphrase",
        "public_key",
        "preshared_key",
        "pre_shared_key",
        "obfs_password",
    }
)


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
    if not isinstance(user_overrides, dict):
        raise ValueError(f"Overrides for user '{username}' must be an object")

    # User entries are credential/endpoint overrides, not arbitrary node patches.
    for key, value in user_overrides.items():
        normalized_key = key.replace("-", "_")
        if normalized_key not in _USER_OVERRIDE_FIELDS or not hasattr(
            new_node, normalized_key
        ):
            raise ValueError(f"User '{username}' cannot override node field '{key}'")
        if normalized_key == "port" and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= 65535
        ):
            raise ValueError(f"Invalid port override for user '{username}'")
        setattr(new_node, normalized_key, value)

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
