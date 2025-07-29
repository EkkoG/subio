"""Composite pattern for node models - recommended approach."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Union
from abc import ABC, abstractmethod


class NodeType(Enum):
    """Supported node types."""

    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    TROJAN = "trojan"
    VLESS = "vless"
    HYSTERIA = "hysteria"
    HYSTERIA2 = "hysteria2"
    SOCKS5 = "socks5"
    HTTP = "http"
    WIREGUARD = "wireguard"
    TUIC = "tuic"
    SSH = "ssh"
    SNELL = "snell"
    MIERU = "mieru"
    ANYTLS = "anytls"


# Components for composition


@dataclass
class BasicAuth:
    """Basic authentication component."""

    username: Optional[str] = None
    password: Optional[str] = None

    def validate(self) -> None:
        if self.username and not self.password:
            raise ValueError("Password required when username is set")


@dataclass
class ECHConfig:
    """Encrypted Client Hello (ECH) configuration."""

    enabled: bool = False
    config: Optional[str] = None  # Base64 encoded ECH config


@dataclass
class TLSConfig:
    """TLS configuration component."""

    enabled: bool = False
    sni: Optional[str] = None
    skip_cert_verify: bool = False
    alpn: Optional[List[str]] = None
    fingerprint: Optional[str] = None
    client_fingerprint: Optional[str] = (
        None  # For utls: chrome, firefox, safari, ios, random
    )
    ech: Optional[ECHConfig] = None
    ca: Optional[str] = None
    ca_str: Optional[str] = None


@dataclass
class RealityConfig:
    """Reality configuration for VLESS."""

    enabled: bool = False
    public_key: Optional[str] = None
    short_id: Optional[str] = None


@dataclass
class SmuxConfig:
    """Sing-mux multiplexing configuration."""

    enabled: bool = False
    protocol: str = "smux"  # smux, yamux, h2mux
    max_connections: Optional[int] = None
    min_streams: Optional[int] = None
    max_streams: Optional[int] = None
    padding: bool = False
    statistic: bool = False
    only_tcp: bool = False


@dataclass
class WebSocketTransport:
    """WebSocket transport configuration."""

    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    max_early_data: Optional[int] = None
    early_data_header_name: Optional[str] = None


@dataclass
class GRPCTransport:
    """gRPC transport configuration."""

    service_name: str
    multi_mode: bool = False


@dataclass
class HTTPTransport:
    """HTTP transport configuration."""

    method: str = "GET"
    path: Optional[List[str]] = None
    headers: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class HTTP2Transport:
    """HTTP/2 transport configuration."""

    host: Optional[List[str]] = None
    path: str = "/"


@dataclass
class QUICTransport:
    """QUIC transport configuration."""

    security: str = "none"  # none, aes-128-gcm, chacha20-poly1305
    key: Optional[str] = None
    header: Dict[str, str] = field(default_factory=dict)


@dataclass
class Transport:
    """Transport layer configuration."""

    type: str = "tcp"  # tcp, ws, http, h2, grpc, quic
    ws: Optional[WebSocketTransport] = None
    grpc: Optional[GRPCTransport] = None
    http: Optional[HTTPTransport] = None
    h2: Optional[HTTP2Transport] = None
    quic: Optional[QUICTransport] = None

    def validate(self) -> None:
        if self.type == "ws" and not self.ws:
            raise ValueError("WebSocket config required for ws transport")
        elif self.type == "grpc" and not self.grpc:
            raise ValueError("gRPC config required for grpc transport")
        elif self.type == "http" and not self.http:
            raise ValueError("HTTP config required for http transport")
        elif self.type == "h2" and not self.h2:
            raise ValueError("HTTP/2 config required for h2 transport")
        elif self.type == "quic" and not self.quic:
            raise ValueError("QUIC config required for quic transport")


# Protocol configurations


@dataclass
class ProtocolConfig(ABC):
    """Base protocol configuration."""

    @abstractmethod
    def validate(self) -> None:
        """Validate protocol-specific settings."""
        pass

    @abstractmethod
    def get_type(self) -> NodeType:
        """Get the protocol type."""
        pass


@dataclass
class ShadowsocksProtocol(ProtocolConfig):
    """Shadowsocks protocol configuration."""

    method: str
    password: str

    # Optional plugin system
    plugin: Optional[str] = None
    plugin_opts: Dict[str, Any] = field(default_factory=dict)

    # UDP over TCP
    udp_over_tcp: bool = False
    udp_over_tcp_version: int = 1

    def validate(self) -> None:
        valid_methods = [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "aes-128-cfb",
            "aes-256-cfb",
            "chacha20-ietf",
            "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ]
        if self.method not in valid_methods:
            raise ValueError(f"Invalid method: {self.method}")

        valid_plugins = ["obfs", "v2ray-plugin", "shadow-tls", "restls"]
        if self.plugin and self.plugin not in valid_plugins:
            raise ValueError(f"Invalid plugin: {self.plugin}")

    def get_type(self) -> NodeType:
        return NodeType.SHADOWSOCKS


@dataclass
class VmessProtocol(ProtocolConfig):
    """VMess protocol configuration."""

    uuid: str
    alter_id: int = 0
    security: str = "auto"  # auto, aes-128-gcm, chacha20-poly1305, none

    def validate(self) -> None:
        if not self.uuid:
            raise ValueError("UUID required")
        valid_security = ["auto", "aes-128-gcm", "chacha20-poly1305", "none"]
        if self.security not in valid_security:
            raise ValueError(f"Invalid security: {self.security}")

    def get_type(self) -> NodeType:
        return NodeType.VMESS


@dataclass
class TrojanProtocol(ProtocolConfig):
    """Trojan protocol configuration."""

    password: str

    def validate(self) -> None:
        if not self.password:
            raise ValueError("Password required")

    def get_type(self) -> NodeType:
        return NodeType.TROJAN


@dataclass
class VlessProtocol(ProtocolConfig):
    """VLESS protocol configuration."""

    uuid: str
    flow: Optional[str] = (
        None  # xtls-rprx-direct, xtls-rprx-vision, xtls-rprx-vision-udp443
    )
    encryption: str = "none"

    def validate(self) -> None:
        if not self.uuid:
            raise ValueError("UUID required")
        valid_flows = [
            "xtls-rprx-direct",
            "xtls-rprx-vision",
            "xtls-rprx-vision-udp443",
        ]
        if self.flow and self.flow not in valid_flows:
            raise ValueError(f"Invalid flow: {self.flow}")

    def get_type(self) -> NodeType:
        return NodeType.VLESS


@dataclass
class HysteriaProtocol(ProtocolConfig):
    """Hysteria protocol configuration."""

    auth: Optional[str] = None
    auth_str: Optional[str] = None
    protocol: str = "udp"
    up_mbps: Optional[Union[int, str]] = None
    down_mbps: Optional[Union[int, str]] = None
    obfs: Optional[str] = None
    recv_window: Optional[int] = None
    recv_window_conn: Optional[int] = None

    def validate(self) -> None:
        if not self.auth and not self.auth_str:
            raise ValueError("Either auth or auth_str required")
        if self.protocol not in ["udp", "wechat-video", "faketcp"]:
            raise ValueError(f"Invalid protocol: {self.protocol}")

    def get_type(self) -> NodeType:
        return NodeType.HYSTERIA


@dataclass
class Hysteria2Protocol(ProtocolConfig):
    """Hysteria2 protocol configuration."""

    password: str
    obfs: Optional[str] = None
    obfs_password: Optional[str] = None
    up_mbps: Optional[Union[int, str]] = None
    down_mbps: Optional[Union[int, str]] = None

    def validate(self) -> None:
        if not self.password:
            raise ValueError("Password required")
        if self.obfs and self.obfs != "salamander" and not self.obfs_password:
            raise ValueError("Obfs password required when obfs is enabled")

    def get_type(self) -> NodeType:
        return NodeType.HYSTERIA2


@dataclass
class HttpProtocol(ProtocolConfig):
    """HTTP/HTTPS proxy protocol configuration."""

    tls: bool = False

    def validate(self) -> None:
        pass  # No specific validation needed

    def get_type(self) -> NodeType:
        return NodeType.HTTP


@dataclass
class Socks5Protocol(ProtocolConfig):
    """SOCKS5 proxy protocol configuration."""

    tls: bool = False

    def validate(self) -> None:
        pass  # No specific validation needed

    def get_type(self) -> NodeType:
        return NodeType.SOCKS5


@dataclass
class WireGuardProtocol(ProtocolConfig):
    """WireGuard protocol configuration."""

    private_key: str
    public_key: str
    preshared_key: Optional[str] = None
    ip: Optional[str] = None
    ipv6: Optional[str] = None
    reserved: Optional[List[int]] = None
    mtu: Optional[int] = None

    def validate(self) -> None:
        if not self.private_key:
            raise ValueError("Private key required")
        if not self.public_key:
            raise ValueError("Public key required")

    def get_type(self) -> NodeType:
        return NodeType.WIREGUARD


@dataclass
class TuicProtocol(ProtocolConfig):
    """TUIC protocol configuration."""

    uuid: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    congestion_control: str = "cubic"
    udp_relay_mode: str = "native"
    reduce_rtt: bool = False
    heartbeat_interval: Optional[int] = None
    alpn: Optional[List[str]] = None
    disable_sni: bool = False
    max_udp_relay_packet_size: Optional[int] = None

    def validate(self) -> None:
        if not self.uuid and not self.token:
            raise ValueError("Either uuid or token required")
        if self.uuid and not self.password:
            raise ValueError("Password required when using uuid")

    def get_type(self) -> NodeType:
        return NodeType.TUIC


@dataclass
class SSHProtocol(ProtocolConfig):
    """SSH protocol configuration."""

    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    host_key: Optional[List[str]] = None
    host_key_algorithms: Optional[List[str]] = None
    client_version: Optional[str] = None

    def validate(self) -> None:
        if not self.username:
            raise ValueError("Username required")
        if not self.password and not self.private_key:
            raise ValueError("Either password or private key required")

    def get_type(self) -> NodeType:
        return NodeType.SSH


@dataclass
class SnellProtocol(ProtocolConfig):
    """Snell protocol configuration."""

    psk: str
    version: int = 2
    obfs_mode: Optional[str] = None  # http or tls
    obfs_host: Optional[str] = None

    def validate(self) -> None:
        if not self.psk:
            raise ValueError("PSK required")
        if self.version not in [1, 2, 3]:
            raise ValueError(f"Invalid version: {self.version}")
        if self.obfs_mode and self.obfs_mode not in ["http", "tls"]:
            raise ValueError(f"Invalid obfs mode: {self.obfs_mode}")

    def get_type(self) -> NodeType:
        return NodeType.SNELL


@dataclass
class MieruProtocol(ProtocolConfig):
    """Mieru protocol configuration."""

    username: str
    password: str
    transport: str = "TCP"
    multiplexing: str = "MULTIPLEXING_LOW"
    port_range: Optional[str] = None  # e.g., "2090-2099"

    def validate(self) -> None:
        if not self.username:
            raise ValueError("Username required")
        if not self.password:
            raise ValueError("Password required")
        if self.transport != "TCP":
            raise ValueError("Only TCP transport supported")

        valid_multiplexing = [
            "MULTIPLEXING_OFF",
            "MULTIPLEXING_LOW",
            "MULTIPLEXING_MIDDLE",
            "MULTIPLEXING_HIGH",
        ]
        if self.multiplexing not in valid_multiplexing:
            raise ValueError(f"Invalid multiplexing: {self.multiplexing}")

    def get_type(self) -> NodeType:
        return NodeType.MIERU


@dataclass
class AnyTLSProtocol(ProtocolConfig):
    """AnyTLS protocol configuration."""

    password: str
    idle_session_check_interval: Optional[int] = None
    idle_session_timeout: Optional[int] = None
    min_idle_session: Optional[int] = None

    def validate(self) -> None:
        if not self.password:
            raise ValueError("Password required")

    def get_type(self) -> NodeType:
        return NodeType.ANYTLS


# Main composite node


@dataclass
class Proxy:
    """Composite node combining all components."""

    # Basic info
    name: str
    server: str
    port: int

    # Protocol configuration
    protocol: ProtocolConfig

    # Optional components
    auth: Optional[BasicAuth] = None
    tls: Optional[TLSConfig] = None
    reality: Optional[RealityConfig] = None
    transport: Optional[Transport] = None
    smux: Optional[SmuxConfig] = None

    # Metadata
    group: Optional[str] = None
    remarks: Optional[str] = None

    # Extension fields
    extra: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate the complete node configuration."""
        # Basic validation
        if not self.name:
            raise ValueError("Name required")
        if not self.server:
            raise ValueError("Server required")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid port: {self.port}")

        # Validate components
        self.protocol.validate()

        if self.auth:
            self.auth.validate()

        if self.transport:
            self.transport.validate()

        # Protocol-specific validation
        if isinstance(self.protocol, TrojanProtocol) and not self.tls:
            self.tls = TLSConfig(enabled=True)  # Trojan requires TLS

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        # Start with common default fields
        result = {
            "name": self.name,
            "type": self.protocol.get_type().value,
            "server": self.server,
            "port": self.port,
            "tfo": False,
            "mptcp": False,
            "ip-version": "dual",
            "skip-cert-verify": False,  # Default to false
        }

        # Add UDP support based on protocol
        if isinstance(
            self.protocol, (ShadowsocksProtocol, VlessProtocol, TrojanProtocol)
        ):
            result["udp"] = True
        elif isinstance(self.protocol, (VmessProtocol, Socks5Protocol)):
            # Check transport for VMess
            if isinstance(self.protocol, VmessProtocol):
                # VMess with certain transports doesn't support UDP
                if self.transport and self.transport.type in ["tcp", "http"]:
                    result["udp"] = self.transport.type != "http"
                elif self.transport and self.transport.type in ["ws", "grpc"]:
                    result["udp"] = False
                else:
                    result["udp"] = True
            else:
                result["udp"] = True
        else:
            result["udp"] = False

        # Add protocol-specific fields
        if isinstance(self.protocol, ShadowsocksProtocol):
            # Map method to cipher for Clash
            result.update(
                {
                    "cipher": self.protocol.method,
                    "password": self.protocol.password,
                }
            )
            if self.protocol.udp_over_tcp:
                result["udp-over-tcp"] = True
                result["udp-over-tcp-version"] = self.protocol.udp_over_tcp_version
            if self.protocol.plugin:
                result["plugin"] = self.protocol.plugin
                result["plugin-opts"] = self.protocol.plugin_opts

        elif isinstance(self.protocol, VmessProtocol):
            result.update(
                {
                    "uuid": self.protocol.uuid,
                    "alterId": self.protocol.alter_id,
                    "cipher": self.protocol.security,
                    "global-padding": False,
                }
            )

        elif isinstance(self.protocol, TrojanProtocol):
            result["password"] = self.protocol.password

        elif isinstance(self.protocol, VlessProtocol):
            result.update(
                {"uuid": self.protocol.uuid, "encryption": self.protocol.encryption}
            )
            if self.protocol.flow:
                result["flow"] = self.protocol.flow

        elif isinstance(self.protocol, HysteriaProtocol):
            if self.protocol.auth:
                result["auth"] = self.protocol.auth
            if self.protocol.auth_str:
                result["auth-str"] = self.protocol.auth_str
            result["protocol"] = self.protocol.protocol
            if self.protocol.up_mbps:
                result["up"] = self.protocol.up_mbps
            if self.protocol.down_mbps:
                result["down"] = self.protocol.down_mbps
            if self.protocol.obfs:
                result["obfs"] = self.protocol.obfs

        elif isinstance(self.protocol, Hysteria2Protocol):
            result["password"] = self.protocol.password
            if self.protocol.obfs:
                result["obfs"] = self.protocol.obfs
                if self.protocol.obfs_password:
                    result["obfs-password"] = self.protocol.obfs_password
            if self.protocol.up_mbps:
                result["up"] = str(self.protocol.up_mbps)
            if self.protocol.down_mbps:
                result["down"] = str(self.protocol.down_mbps)

        elif isinstance(self.protocol, (HttpProtocol, Socks5Protocol)):
            # Auth is handled by the auth component
            if isinstance(self.protocol, HttpProtocol) and self.protocol.tls:
                result["tls"] = True

        elif isinstance(self.protocol, WireGuardProtocol):
            result.update(
                {
                    "private-key": self.protocol.private_key,
                    "public-key": self.protocol.public_key,
                }
            )
            if self.protocol.preshared_key:
                result["preshared-key"] = self.protocol.preshared_key
            if self.protocol.ip:
                result["ip"] = self.protocol.ip
            if self.protocol.ipv6:
                result["ipv6"] = self.protocol.ipv6
            if self.protocol.reserved:
                result["reserved"] = self.protocol.reserved
            if self.protocol.mtu:
                result["mtu"] = self.protocol.mtu

        elif isinstance(self.protocol, TuicProtocol):
            if self.protocol.uuid:
                result["uuid"] = self.protocol.uuid
            if self.protocol.password:
                result["password"] = self.protocol.password
            if self.protocol.token:
                result["token"] = self.protocol.token
            result["congestion-controller"] = self.protocol.congestion_control
            result["udp-relay-mode"] = self.protocol.udp_relay_mode
            if self.protocol.reduce_rtt:
                result["reduce-rtt"] = self.protocol.reduce_rtt
            if self.protocol.heartbeat_interval:
                result["heartbeat-interval"] = self.protocol.heartbeat_interval
            if self.protocol.alpn:
                result["alpn"] = self.protocol.alpn
            if self.protocol.disable_sni:
                result["disable-sni"] = self.protocol.disable_sni
            if self.protocol.max_udp_relay_packet_size:
                result["max-udp-relay-packet-size"] = (
                    self.protocol.max_udp_relay_packet_size
                )

        elif isinstance(self.protocol, SSHProtocol):
            result["username"] = self.protocol.username
            if self.protocol.password:
                result["password"] = self.protocol.password
            if self.protocol.private_key:
                result["private-key"] = self.protocol.private_key
            if self.protocol.private_key_passphrase:
                result["private-key-passphrase"] = self.protocol.private_key_passphrase
            if self.protocol.host_key:
                result["host-key"] = self.protocol.host_key
            if self.protocol.host_key_algorithms:
                result["host-key-algorithms"] = self.protocol.host_key_algorithms
            if self.protocol.client_version:
                result["client-version"] = self.protocol.client_version

        elif isinstance(self.protocol, SnellProtocol):
            result["psk"] = self.protocol.psk
            result["version"] = self.protocol.version
            if self.protocol.obfs_mode:
                result["obfs-opts"] = {
                    "mode": self.protocol.obfs_mode,
                    "host": self.protocol.obfs_host or "bing.com",
                }

        elif isinstance(self.protocol, MieruProtocol):
            result["username"] = self.protocol.username
            result["password"] = self.protocol.password
            result["transport"] = self.protocol.transport
            if self.protocol.port_range:
                result["port-range"] = self.protocol.port_range
            if self.protocol.multiplexing != "MULTIPLEXING_LOW":
                result["multiplexing"] = self.protocol.multiplexing

        elif isinstance(self.protocol, AnyTLSProtocol):
            result["password"] = self.protocol.password
            if self.protocol.idle_session_check_interval:
                result["idle-session-check-interval"] = (
                    self.protocol.idle_session_check_interval
                )
            if self.protocol.idle_session_timeout:
                result["idle-session-timeout"] = self.protocol.idle_session_timeout
            if self.protocol.min_idle_session:
                result["min-idle-session"] = self.protocol.min_idle_session

        # Add auth if present
        if self.auth and self.auth.username:
            result["username"] = self.auth.username
            if self.auth.password:
                result["password"] = self.auth.password

        # Add TLS config
        if self.tls and self.tls.enabled:
            result["tls"] = True
            if self.tls.sni:
                result["sni"] = self.tls.sni
            result["skip-cert-verify"] = self.tls.skip_cert_verify
            if self.tls.alpn:
                result["alpn"] = self.tls.alpn
            if self.tls.fingerprint:
                result["fingerprint"] = self.tls.fingerprint
            if self.tls.client_fingerprint:
                result["client-fingerprint"] = self.tls.client_fingerprint
            if self.tls.ech and self.tls.ech.enabled:
                result["ech-opts"] = {"enable": True}
                if self.tls.ech.config:
                    result["ech-opts"]["config"] = self.tls.ech.config
            if self.tls.ca:
                result["ca"] = self.tls.ca
            if self.tls.ca_str:
                result["ca-str"] = self.tls.ca_str
        elif isinstance(self.protocol, (HttpProtocol, Socks5Protocol)):
            # Add explicit tls field for HTTP/SOCKS5
            if hasattr(self.protocol, "tls"):
                result["tls"] = self.protocol.tls
        else:
            # For protocols that typically don't use TLS
            result["tls"] = False

        # Add Reality config
        if self.reality and self.reality.enabled:
            result["reality-opts"] = {}
            if self.reality.public_key:
                result["reality-opts"]["public-key"] = self.reality.public_key
            if self.reality.short_id:
                result["reality-opts"]["short-id"] = self.reality.short_id

        # Add transport
        if self.transport and self.transport.type != "tcp":
            result["network"] = self.transport.type

            if self.transport.type == "ws" and self.transport.ws:
                ws_opts = {}
                if self.transport.ws.path != "/":
                    ws_opts["path"] = self.transport.ws.path
                if self.transport.ws.headers:
                    ws_opts["headers"] = self.transport.ws.headers
                if ws_opts:
                    result["ws-opts"] = ws_opts

            elif self.transport.type == "grpc" and self.transport.grpc:
                result["grpc-opts"] = {
                    "grpc-service-name": self.transport.grpc.service_name
                }

        # Add smux config
        if self.smux and self.smux.enabled:
            smux_config = {"enabled": True, "protocol": self.smux.protocol}
            if self.smux.max_connections:
                smux_config["max-connections"] = self.smux.max_connections
            if self.smux.min_streams:
                smux_config["min-streams"] = self.smux.min_streams
            if self.smux.max_streams:
                smux_config["max-streams"] = self.smux.max_streams
            if self.smux.padding:
                smux_config["padding"] = self.smux.padding
            if self.smux.statistic:
                smux_config["statistic"] = self.smux.statistic
            if self.smux.only_tcp:
                smux_config["only-tcp"] = self.smux.only_tcp
            result["smux"] = smux_config

        # Add metadata
        if self.group:
            result["group"] = self.group
        if self.remarks:
            result["remarks"] = self.remarks

        # Add extra fields
        result.update(self.extra)

        # Apply fingerprint from extra if not already set
        if "fingerprint" in self.extra and "fingerprint" not in result:
            result["fingerprint"] = self.extra["fingerprint"]

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proxy":
        """Create node from dictionary."""
        node_type = data.get("type", "").lower()

        # Create protocol config
        if node_type in ["ss", "shadowsocks"]:
            protocol = ShadowsocksProtocol(
                method=data.get("method", "aes-256-gcm"),
                password=data.get("password", ""),
                plugin=data.get("plugin"),
                plugin_opts=data.get("plugin-opts", {}),
            )
        elif node_type == "vmess":
            protocol = VmessProtocol(
                uuid=data.get("uuid", ""),
                alter_id=data.get("alterId", 0),
                security=data.get("cipher", "auto"),
            )
        elif node_type == "trojan":
            protocol = TrojanProtocol(password=data.get("password", ""))
        elif node_type == "vless":
            protocol = VlessProtocol(
                uuid=data.get("uuid", ""),
                flow=data.get("flow"),
                encryption=data.get("encryption", "none"),
            )
        elif node_type in ["hysteria", "hy"]:
            protocol = HysteriaProtocol(
                auth=data.get("auth"),
                auth_str=data.get("auth-str") or data.get("auth_str"),
                protocol=data.get("protocol", "udp"),
                up_mbps=data.get("up"),
                down_mbps=data.get("down"),
                obfs=data.get("obfs"),
            )
        elif node_type in ["hysteria2", "hy2"]:
            protocol = Hysteria2Protocol(
                password=data.get("password", ""),
                obfs=data.get("obfs"),
                obfs_password=data.get("obfs-password") or data.get("obfs_password"),
            )
        elif node_type in ["http", "https"]:
            protocol = HttpProtocol(tls=data.get("tls", False) or node_type == "https")
        elif node_type in ["socks5", "socks"]:
            protocol = Socks5Protocol(tls=data.get("tls", False))
        elif node_type in ["wireguard", "wg"]:
            protocol = WireGuardProtocol(
                private_key=data.get("private-key", ""),
                public_key=data.get("public-key", ""),
                preshared_key=data.get("pre-shared-key") or data.get("preshared-key"),
                ip=data.get("ip"),
                ipv6=data.get("ipv6"),
                reserved=data.get("reserved"),
                mtu=data.get("mtu"),
            )
        elif node_type == "tuic":
            protocol = TuicProtocol(
                uuid=data.get("uuid"),
                password=data.get("password"),
                token=data.get("token"),
                congestion_control=data.get("congestion-controller", "cubic"),
                udp_relay_mode=data.get("udp-relay-mode", "native"),
                reduce_rtt=data.get("reduce-rtt", False),
                heartbeat_interval=data.get("heartbeat-interval"),
                alpn=data.get("alpn"),
                disable_sni=data.get("disable-sni", False),
                max_udp_relay_packet_size=data.get("max-udp-relay-packet-size"),
            )
        elif node_type == "ssh":
            protocol = SSHProtocol(
                username=data.get("username", "root"),
                password=data.get("password"),
                private_key=data.get("private-key") or data.get("privateKey"),
                private_key_passphrase=data.get("private-key-passphrase"),
                host_key=data.get("host-key"),
                host_key_algorithms=data.get("host-key-algorithms"),
                client_version=data.get("client-version"),
            )
        elif node_type == "snell":
            obfs_opts = data.get("obfs-opts", {})
            protocol = SnellProtocol(
                psk=data.get("psk", ""),
                version=data.get("version", 2),
                obfs_mode=obfs_opts.get("mode") if obfs_opts else None,
                obfs_host=obfs_opts.get("host") if obfs_opts else None,
            )
        elif node_type == "mieru":
            protocol = MieruProtocol(
                username=data.get("username", ""),
                password=data.get("password", ""),
                transport=data.get("transport", "TCP"),
                multiplexing=data.get("multiplexing", "MULTIPLEXING_LOW"),
                port_range=data.get("port-range"),
            )
        elif node_type == "anytls":
            protocol = AnyTLSProtocol(
                password=data.get("password", ""),
                idle_session_check_interval=data.get("idle-session-check-interval"),
                idle_session_timeout=data.get("idle-session-timeout"),
                min_idle_session=data.get("min-idle-session"),
            )
        else:
            raise ValueError(f"Unsupported node type: {node_type}")

        # Create auth if needed
        auth = None
        if "username" in data:
            auth = BasicAuth(
                username=data.get("username"), password=data.get("password")
            )

        # Create TLS config
        tls = None
        if data.get("tls"):
            tls = TLSConfig(
                enabled=True,
                sni=data.get("sni"),
                skip_cert_verify=data.get("skip-cert-verify", False),
                alpn=data.get("alpn"),
            )

        # Create transport
        transport = None
        network = data.get("network", "tcp")
        if network != "tcp":
            transport = Transport(type=network)

            if network == "ws":
                ws_opts = data.get("ws-opts", {})
                transport.ws = WebSocketTransport(
                    path=ws_opts.get("path", "/"), headers=ws_opts.get("headers", {})
                )
            elif network == "grpc":
                grpc_opts = data.get("grpc-opts", {})
                transport.grpc = GRPCTransport(
                    service_name=grpc_opts.get("grpc-service-name", "")
                )

        # Create node
        node = cls(
            name=data.get("name", "Unknown"),
            server=data.get("server", ""),
            port=data.get("port", 0),
            protocol=protocol,
            auth=auth,
            tls=tls,
            transport=transport,
            group=data.get("group"),
            remarks=data.get("remarks"),
        )

        # Add unknown fields to extra
        known_fields = {
            "name",
            "type",
            "server",
            "port",
            "method",
            "password",
            "uuid",
            "alterId",
            "cipher",
            "flow",
            "encryption",
            "username",
            "tls",
            "sni",
            "skip-cert-verify",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
            "plugin",
            "plugin-opts",
            "group",
            "remarks",
        }

        for key, value in data.items():
            if key not in known_fields:
                node.extra[key] = value

        return node
