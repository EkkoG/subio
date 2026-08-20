from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from subio_v2.model.records import NodeRecord

if TYPE_CHECKING:
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
    GOST_RELAY = "gost-relay"
    REMATCH = "rematch"
    SHADOWQUIC = "shadowquic"
    SUDOKU = "sudoku"
    MASQUE = "masque"
    TRUSTTUNNEL = "trusttunnel"
    OPENVPN = "openvpn"
    TAILSCALE = "tailscale"
    DIRECT = "direct"
    REJECT = "reject"
    DNS = "dns"
    SOURCE_PASSTHROUGH = "source-passthrough"


@dataclass
class TLSSettings:
    enabled: bool = False
    server_name: Optional[str] = None  # sni
    alpn: Optional[List[str]] = None
    skip_cert_verify: bool = False
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


class MieruTransport(StrEnum):
    TCP = "TCP"
    UDP = "UDP"


class MieruMultiplexing(StrEnum):
    DEFAULT = "MULTIPLEXING_DEFAULT"
    OFF = "MULTIPLEXING_OFF"
    LOW = "MULTIPLEXING_LOW"
    MIDDLE = "MULTIPLEXING_MIDDLE"
    HIGH = "MULTIPLEXING_HIGH"


class MieruHandshakeMode(StrEnum):
    DEFAULT = "HANDSHAKE_DEFAULT"
    STANDARD = "HANDSHAKE_STANDARD"
    NO_WAIT = "HANDSHAKE_NO_WAIT"


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
    host: Optional[Union[str, List[str]]] = None  # h2/xhttp host
    method: Optional[str] = "GET"  # http method
    grpc_service_name: Optional[str] = None
    xhttp_mode: Optional[str] = None
    max_early_data: Optional[int] = None
    early_data_header_name: Optional[str] = None
    # Unmapped nested transport fields, keyed by Clash option block (e.g. ws-opts).
    extra: Dict[str, Dict[str, Any]] = field(default_factory=dict)

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
    interface_name: Optional[str] = None
    routing_mark: Optional[int] = None
    surge_options: SurgePolicyOptions = field(default_factory=SurgePolicyOptions)
    shadow_tls: ShadowTLSSettings = field(default_factory=ShadowTLSSettings)
    record: NodeRecord = field(default_factory=NodeRecord, repr=False, compare=False)

    @property
    def original_name(self) -> str | None:
        return self.record.original_name

    @original_name.setter
    def original_name(self, value: str | None) -> None:
        self.record.original_name = value

    @property
    def extra(self) -> dict[str, Any]:
        return self.record.extra

    @extra.setter
    def extra(self, value: dict[str, Any]) -> None:
        self.record.extra = value

    @property
    def source_extensions(self) -> dict[str, Any]:
        return self.record.source_extensions

    @source_extensions.setter
    def source_extensions(self, value: dict[str, Any]) -> None:
        self.record.source_extensions = value

    @property
    def source_provider(self) -> str | None:
        return self.record.source_provider

    @source_provider.setter
    def source_provider(self, value: str | None) -> None:
        self.record.source_provider = value

    @property
    def source_context(self) -> DialectContext | None:
        return self.record.source_context

    @source_context.setter
    def source_context(self, value: DialectContext | None) -> None:
        self.record.source_context = value


@dataclass
class ShadowsocksNode(BaseNode):
    type: Protocol = field(default=Protocol.SHADOWSOCKS)
    cipher: str = "chacha20-ietf-poly1305"
    password: str = field(default="", repr=False)
    udp_port: Optional[int] = None
    plugin: Optional[str] = None
    plugin_opts: Optional[Dict[str, Any]] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class ShadowsocksRNode(BaseNode):
    type: Protocol = field(default=Protocol.SHADOWSOCKSR)
    cipher: str = ""
    password: str = ""
    obfs: str = ""
    ssr_protocol: str = ""
    obfs_param: Optional[str] = None
    protocol_param: Optional[str] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class VmessNode(BaseNode):
    type: Protocol = field(default=Protocol.VMESS)
    uuid: str = field(default="", repr=False)
    alter_id: int = 0
    cipher: str = "auto"
    global_padding: bool = False
    vmess_aead: bool = False  # Surge-specific: vmess-aead parameter
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)
    packet_encoding: Optional[str] = None

@dataclass
class VlessNode(BaseNode):
    type: Protocol = field(default=Protocol.VLESS)
    uuid: str = field(default="", repr=False)
    flow: Optional[str] = None  # xtls-rprx-vision
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)
    packet_encoding: Optional[str] = None

@dataclass
class TrojanNode(BaseNode):
    type: Protocol = field(default=Protocol.TROJAN)
    password: str = field(default="", repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)
    transport: TransportSettings = field(default_factory=TransportSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class Socks5Node(BaseNode):
    type: Protocol = field(default=Protocol.SOCKS5)
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)

@dataclass
class HttpNode(BaseNode):
    type: Protocol = field(default=Protocol.HTTP)
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    headers: Optional[Dict[str, str]] = None
    variant: HttpVariant = HttpVariant.AUTO
    max_streams: Optional[int] = None
    tls: TLSSettings = field(default_factory=TLSSettings)

@dataclass
class WireguardPeer:
    server: str
    port: int
    public_key: str
    allowed_ips: List[str]
    preshared_key: Optional[str] = field(default=None, repr=False)
    reserved: Optional[List[int]] = None


@dataclass
class WireguardNode(BaseNode):
    type: Protocol = field(default=Protocol.WIREGUARD)
    private_key: str = field(default="", repr=False)
    public_key: str = ""
    preshared_key: Optional[str] = None
    interface_ip: Optional[Union[str, List[str]]] = None
    interface_ipv6: Optional[Union[str, List[str]]] = None
    allowed_ips: Optional[List[str]] = None
    reserved: Optional[List[int]] = None
    mtu: Optional[int] = None
    workers: Optional[int] = None
    persistent_keepalive: Optional[int] = None
    amnezia_wg_option: Optional[Dict[str, Any]] = None
    peers: Optional[List[WireguardPeer]] = None
    remote_dns_resolve: Optional[bool] = None
    dns_servers: Optional[List[str]] = None
    refresh_server_ip_interval: Optional[int] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class TailscaleNode(BaseNode):
    type: Protocol = field(default=Protocol.TAILSCALE)
    hostname: Optional[str] = None
    auth_key: Optional[str] = field(default=None, repr=False)
    interactive_login: bool = False
    control_url: Optional[str] = None
    state_dir: Optional[str] = None
    ephemeral: bool = False
    accept_routes: bool = False
    exit_node: Optional[str] = None
    exit_node_auto_fallback: bool = False
    exit_node_allow_lan_access: bool = False
    derp_only: bool = False
    auto_add_magic_dns_rule: Optional[bool] = None
    idle_keepalive: Optional[int] = None
    prefer_ipv6: bool = False
    dns_servers: Optional[List[str]] = None
    mtu: Optional[int] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class MasqueNode(BaseNode):
    type: Protocol = field(default=Protocol.MASQUE)
    mode: MasqueMode = MasqueMode.FORWARD_PROXY
    transport: str = "h3"
    connect_uri: Optional[str] = None
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

@dataclass
class TrustTunnelNode(BaseNode):
    type: Protocol = field(default=Protocol.TRUSTTUNNEL)
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

@dataclass
class DirectNode(BaseNode):
    type: Protocol = field(default=Protocol.DIRECT)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class DNSNode(BaseNode):
    """Mihomo DNS outbound that redirects traffic to the internal DNS module."""

    type: Protocol = field(default=Protocol.DNS)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class RematchNode(BaseNode):
    type: Protocol = field(default=Protocol.REMATCH)
    target_rematch_name: Optional[str] = None
    target_sub_rule: Optional[str] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class GostRelayNode(BaseNode):
    type: Protocol = field(default=Protocol.GOST_RELAY)
    forward: bool = False
    mux: bool = False
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=TLSSettings)
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class ShadowQUICNode(BaseNode):
    type: Protocol = field(default=Protocol.SHADOWQUIC)
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    quic_versions: Optional[List[str]] = None
    udp_over_stream: bool = False
    zero_rtt: bool = False
    keep_alive_interval: Optional[int] = None
    congestion_controller: Optional[str] = None
    up: Optional[str] = None
    down: Optional[str] = None
    cwnd: Optional[int] = None
    bbr_profile: Optional[str] = None
    recv_window_conn: Optional[int] = None
    recv_window: Optional[int] = None
    disable_mtu_discovery: bool = False
    max_datagram_frame_size: Optional[int] = None
    max_open_streams: Optional[int] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class OpenVPNNode(BaseNode):
    type: Protocol = field(default=Protocol.OPENVPN)
    proto: str = "udp"
    dev: str = "tun"
    cipher: str = "AES-128-GCM"
    data_ciphers: Optional[List[str]] = None
    data_ciphers_fallback: Optional[str] = None
    auth: str = "SHA256"
    comp_lzo: str = "no"
    ca: str = field(default="", repr=False)
    certificate: Optional[str] = field(default=None, repr=False)
    private_key: Optional[str] = field(default=None, repr=False)
    tls_auth: Optional[str] = field(default=None, repr=False)
    key_direction: Optional[str] = None
    tls_crypt: Optional[str] = field(default=None, repr=False)
    tls_crypt_v2: Optional[str] = field(default=None, repr=False)
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    peer_info: Optional[Dict[str, str]] = field(default=None, repr=False)
    ping: int = 0
    ping_restart: int = 0
    handshake_timeout: int = 0
    mtu: int = 1500
    remote_dns_resolve: bool = False
    dns_servers: Optional[List[str]] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class SudokuHTTPMaskSettings:
    disable: Optional[bool] = None
    mode: Optional[str] = None
    tls: Optional[bool] = None
    host: Optional[str] = None
    path_root: Optional[str] = None
    multiplex: Optional[str] = None


@dataclass
class SudokuNode(BaseNode):
    type: Protocol = field(default=Protocol.SUDOKU)
    key: str = field(default="", repr=False)
    aead_method: str = "chacha20-poly1305"
    padding_min: int = 10
    padding_max: int = 30
    table_type: str = "prefer_entropy"
    enable_pure_downlink: bool = True
    multiplex: str = "off"
    httpmask: Optional[SudokuHTTPMaskSettings] = None
    custom_table: Optional[str] = None
    custom_tables: Optional[List[str]] = None
    legacy_http_mask: Optional[bool] = None
    legacy_http_mask_mode: Optional[str] = None
    legacy_http_mask_tls: Optional[bool] = None
    legacy_http_mask_host: Optional[str] = None
    legacy_path_root: Optional[str] = None
    legacy_http_mask_strategy: Optional[str] = None
    legacy_http_mask_multiplex: Optional[str] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class RejectNode(BaseNode):
    type: Protocol = field(default=Protocol.REJECT)
    mode: RejectMode = RejectMode.REJECT
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if not isinstance(self.mode, RejectMode):
            self.mode = RejectMode(self.mode)


@dataclass
class AnyTLSNode(BaseNode):
    type: Protocol = field(default=Protocol.ANYTLS)
    password: str = field(default="", repr=False)
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    reuse: bool = True
    idle_session_check_interval: Optional[int] = None
    idle_session_timeout: Optional[int] = None
    min_idle_session: Optional[int] = None

@dataclass
class HysteriaNode(BaseNode):
    type: Protocol = field(default=Protocol.HYSTERIA)
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
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class Hysteria2Node(BaseNode):
    type: Protocol = field(default=Protocol.HYSTERIA2)
    password: str = field(default="", repr=False)
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    up: Optional[str] = None
    down: Optional[str] = None
    obfs: Optional[str] = None
    obfs_password: Optional[str] = field(default=None, repr=False)
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class SSHNode(BaseNode):
    type: Protocol = field(default=Protocol.SSH)
    username: str = ""
    password: Optional[str] = field(default=None, repr=False)
    private_key: Optional[str] = field(default=None, repr=False)
    private_key_passphrase: Optional[str] = field(default=None, repr=False)
    keystore_id: Optional[str] = None  # Reference to Keystore entry ID
    host_key: Optional[List[str]] = None
    host_key_algorithms: Optional[List[str]] = None
    idle_timeout: Optional[int] = None
    server_fingerprints: Optional[List[str]] = None

@dataclass
class SnellNode(BaseNode):
    type: Protocol = field(default=Protocol.SNELL)
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

@dataclass
class MieruNode(BaseNode):
    type: Protocol = field(default=Protocol.MIERU)
    port_range: Optional[str] = None
    transport: Optional[MieruTransport] = None
    username: str = ""
    password: str = field(default="", repr=False)
    multiplexing: Optional[MieruMultiplexing] = None
    handshake_mode: Optional[MieruHandshakeMode] = None
    traffic_pattern: Optional[str] = None
    smux: SmuxSettings = field(default_factory=SmuxSettings)

    def __post_init__(self):
        if self.port_range is not None:
            self.port_range = str(self.port_range)
        if self.transport is not None and not isinstance(
            self.transport, MieruTransport
        ):
            self.transport = MieruTransport(self.transport)
        if self.multiplexing is not None and not isinstance(
            self.multiplexing, MieruMultiplexing
        ):
            self.multiplexing = MieruMultiplexing(self.multiplexing)
        if self.handshake_mode is not None and not isinstance(
            self.handshake_mode, MieruHandshakeMode
        ):
            self.handshake_mode = MieruHandshakeMode(self.handshake_mode)


@dataclass
class JuicityNode(BaseNode):
    type: Protocol = field(default=Protocol.JUICITY)
    uuid: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))

@dataclass
class TUICNode(BaseNode):
    type: Protocol = field(default=Protocol.TUIC)
    token: Optional[str] = field(default=None, repr=False)  # TUIC v4 uses token
    password: Optional[str] = field(default=None, repr=False)  # TUIC v5 password
    uuid: Optional[str] = field(default=None, repr=False)  # TUIC v5 uses uuid
    version: Optional[int] = None  # 4 or 5
    ports: Optional[str] = None
    hop_interval: Optional[int] = None
    tls: TLSSettings = field(default_factory=lambda: TLSSettings(enabled=True))
    smux: SmuxSettings = field(default_factory=SmuxSettings)

@dataclass
class SourcePassthroughNode(BaseNode):
    """Opaque source record that may only be emitted back to its source dialect."""

    type: Protocol = field(default=Protocol.SOURCE_PASSTHROUGH, init=False)

    @property
    def original_type(self) -> str:
        return self.record.opaque_type or ""

    @original_type.setter
    def original_type(self, value: str) -> None:
        self.record.opaque_type = value

    @property
    def raw(self) -> Any:
        return self.record.opaque_raw

    @raw.setter
    def raw(self, value: Any) -> None:
        self.record.opaque_raw = value


# ProtocolDefinition is the concrete model authority; general pipelines only
# require the shared semantic node contract.
Node = BaseNode
