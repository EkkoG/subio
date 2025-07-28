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
class TLSConfig:
    """TLS configuration component."""
    enabled: bool = False
    sni: Optional[str] = None
    skip_cert_verify: bool = False
    alpn: Optional[List[str]] = None
    fingerprint: Optional[str] = None


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
class Transport:
    """Transport layer configuration."""
    type: str = "tcp"  # tcp, ws, http, grpc, quic
    ws: Optional[WebSocketTransport] = None
    grpc: Optional[GRPCTransport] = None
    
    def validate(self) -> None:
        if self.type == "ws" and not self.ws:
            raise ValueError("WebSocket config required for ws transport")
        elif self.type == "grpc" and not self.grpc:
            raise ValueError("gRPC config required for grpc transport")


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
    
    def validate(self) -> None:
        valid_methods = [
            'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
            'aes-128-cfb', 'aes-256-cfb', 'chacha20-ietf', 'xchacha20-ietf-poly1305'
        ]
        if self.method not in valid_methods:
            raise ValueError(f"Invalid method: {self.method}")
    
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
        valid_security = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']
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
    flow: Optional[str] = None  # xtls-rprx-direct, xtls-rprx-vision
    encryption: str = "none"
    
    def validate(self) -> None:
        if not self.uuid:
            raise ValueError("UUID required")
        if self.flow and not self.flow.startswith('xtls-'):
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
        if self.protocol not in ['udp', 'wechat-video', 'faketcp']:
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
    transport: Optional[Transport] = None
    
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
            'name': self.name,
            'type': self.protocol.get_type().value,
            'server': self.server,
            'port': self.port,
            'tfo': False,
            'mptcp': False,
            'ip-version': 'dual',
            'skip-cert-verify': False  # Default to false
        }
        
        # Add UDP support based on protocol
        if isinstance(self.protocol, (ShadowsocksProtocol, VlessProtocol, TrojanProtocol)):
            result['udp'] = True
        elif isinstance(self.protocol, (VmessProtocol, Socks5Protocol)):
            # Check transport for VMess
            if isinstance(self.protocol, VmessProtocol):
                # VMess with certain transports doesn't support UDP
                if self.transport and self.transport.type in ['tcp', 'http']:
                    result['udp'] = self.transport.type != 'http'
                elif self.transport and self.transport.type in ['ws', 'grpc']:
                    result['udp'] = False
                else:
                    result['udp'] = True
            else:
                result['udp'] = True
        else:
            result['udp'] = False
        
        # Add protocol-specific fields
        if isinstance(self.protocol, ShadowsocksProtocol):
            # Map method to cipher for Clash
            result.update({
                'cipher': self.protocol.method,
                'password': self.protocol.password,
                'udp-over-tcp': False,
                'udp-over-tcp-version': 1
            })
            if self.protocol.plugin:
                result['plugin'] = self.protocol.plugin
                result['plugin-opts'] = self.protocol.plugin_opts
        
        elif isinstance(self.protocol, VmessProtocol):
            result.update({
                'uuid': self.protocol.uuid,
                'alterId': self.protocol.alter_id,
                'cipher': self.protocol.security,
                'global-padding': False
            })
        
        elif isinstance(self.protocol, TrojanProtocol):
            result['password'] = self.protocol.password
        
        elif isinstance(self.protocol, VlessProtocol):
            result.update({
                'uuid': self.protocol.uuid,
                'encryption': self.protocol.encryption
            })
            if self.protocol.flow:
                result['flow'] = self.protocol.flow
        
        elif isinstance(self.protocol, HysteriaProtocol):
            if self.protocol.auth:
                result['auth'] = self.protocol.auth
            if self.protocol.auth_str:
                result['auth-str'] = self.protocol.auth_str
            result['protocol'] = self.protocol.protocol
            if self.protocol.up_mbps:
                result['up'] = self.protocol.up_mbps
            if self.protocol.down_mbps:
                result['down'] = self.protocol.down_mbps
            if self.protocol.obfs:
                result['obfs'] = self.protocol.obfs
        
        elif isinstance(self.protocol, Hysteria2Protocol):
            result['password'] = self.protocol.password
            if self.protocol.obfs:
                result['obfs'] = self.protocol.obfs
                if self.protocol.obfs_password:
                    result['obfs-password'] = self.protocol.obfs_password
        
        elif isinstance(self.protocol, (HttpProtocol, Socks5Protocol)):
            # Auth is handled by the auth component
            if isinstance(self.protocol, HttpProtocol) and self.protocol.tls:
                result['tls'] = True
        
        # Add auth if present
        if self.auth and self.auth.username:
            result['username'] = self.auth.username
            if self.auth.password:
                result['password'] = self.auth.password
        
        # Add TLS config
        if self.tls and self.tls.enabled:
            result['tls'] = True
            if self.tls.sni:
                result['sni'] = self.tls.sni
            result['skip-cert-verify'] = self.tls.skip_cert_verify
            if self.tls.alpn:
                result['alpn'] = self.tls.alpn
            if self.tls.fingerprint:
                result['fingerprint'] = self.tls.fingerprint
        elif isinstance(self.protocol, (HttpProtocol, Socks5Protocol)):
            # Add explicit tls field for HTTP/SOCKS5
            if hasattr(self.protocol, 'tls'):
                result['tls'] = self.protocol.tls
        else:
            # For protocols that typically don't use TLS
            result['tls'] = False
        
        # Add transport
        if self.transport and self.transport.type != 'tcp':
            result['network'] = self.transport.type
            
            if self.transport.type == 'ws' and self.transport.ws:
                ws_opts = {}
                if self.transport.ws.path != '/':
                    ws_opts['path'] = self.transport.ws.path
                if self.transport.ws.headers:
                    ws_opts['headers'] = self.transport.ws.headers
                if ws_opts:
                    result['ws-opts'] = ws_opts
            
            elif self.transport.type == 'grpc' and self.transport.grpc:
                result['grpc-opts'] = {
                    'grpc-service-name': self.transport.grpc.service_name
                }
        
        # Add metadata
        if self.group:
            result['group'] = self.group
        if self.remarks:
            result['remarks'] = self.remarks
        
        # Add extra fields
        result.update(self.extra)
        
        # Apply fingerprint from extra if not already set
        if 'fingerprint' in self.extra and 'fingerprint' not in result:
            result['fingerprint'] = self.extra['fingerprint']
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Proxy':
        """Create node from dictionary."""
        node_type = data.get('type', '').lower()
        
        # Create protocol config
        if node_type in ['ss', 'shadowsocks']:
            protocol = ShadowsocksProtocol(
                method=data.get('method', 'aes-256-gcm'),
                password=data.get('password', ''),
                plugin=data.get('plugin'),
                plugin_opts=data.get('plugin-opts', {})
            )
        elif node_type == 'vmess':
            protocol = VmessProtocol(
                uuid=data.get('uuid', ''),
                alter_id=data.get('alterId', 0),
                security=data.get('cipher', 'auto')
            )
        elif node_type == 'trojan':
            protocol = TrojanProtocol(
                password=data.get('password', '')
            )
        elif node_type == 'vless':
            protocol = VlessProtocol(
                uuid=data.get('uuid', ''),
                flow=data.get('flow'),
                encryption=data.get('encryption', 'none')
            )
        elif node_type in ['hysteria', 'hy']:
            protocol = HysteriaProtocol(
                auth=data.get('auth'),
                auth_str=data.get('auth-str') or data.get('auth_str'),
                protocol=data.get('protocol', 'udp'),
                up_mbps=data.get('up'),
                down_mbps=data.get('down'),
                obfs=data.get('obfs')
            )
        elif node_type in ['hysteria2', 'hy2']:
            protocol = Hysteria2Protocol(
                password=data.get('password', ''),
                obfs=data.get('obfs'),
                obfs_password=data.get('obfs-password') or data.get('obfs_password')
            )
        elif node_type in ['http', 'https']:
            protocol = HttpProtocol(
                tls=data.get('tls', False) or node_type == 'https'
            )
        elif node_type in ['socks5', 'socks']:
            protocol = Socks5Protocol(
                tls=data.get('tls', False)
            )
        else:
            raise ValueError(f"Unsupported node type: {node_type}")
        
        # Create auth if needed
        auth = None
        if 'username' in data:
            auth = BasicAuth(
                username=data.get('username'),
                password=data.get('password')
            )
        
        # Create TLS config
        tls = None
        if data.get('tls'):
            tls = TLSConfig(
                enabled=True,
                sni=data.get('sni'),
                skip_cert_verify=data.get('skip-cert-verify', False),
                alpn=data.get('alpn')
            )
        
        # Create transport
        transport = None
        network = data.get('network', 'tcp')
        if network != 'tcp':
            transport = Transport(type=network)
            
            if network == 'ws':
                ws_opts = data.get('ws-opts', {})
                transport.ws = WebSocketTransport(
                    path=ws_opts.get('path', '/'),
                    headers=ws_opts.get('headers', {})
                )
            elif network == 'grpc':
                grpc_opts = data.get('grpc-opts', {})
                transport.grpc = GRPCTransport(
                    service_name=grpc_opts.get('grpc-service-name', '')
                )
        
        # Create node
        node = cls(
            name=data.get('name', 'Unknown'),
            server=data.get('server', ''),
            port=data.get('port', 0),
            protocol=protocol,
            auth=auth,
            tls=tls,
            transport=transport,
            group=data.get('group'),
            remarks=data.get('remarks')
        )
        
        # Add unknown fields to extra
        known_fields = {
            'name', 'type', 'server', 'port', 'method', 'password',
            'uuid', 'alterId', 'cipher', 'flow', 'encryption',
            'username', 'tls', 'sni', 'skip-cert-verify', 'alpn',
            'network', 'ws-opts', 'grpc-opts', 'plugin', 'plugin-opts',
            'group', 'remarks'
        }
        
        for key, value in data.items():
            if key not in known_fields:
                node.extra[key] = value
        
        return node