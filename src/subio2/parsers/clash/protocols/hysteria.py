"""Hysteria protocol parsers for Clash format."""
from typing import Dict, Any, Optional
from ....models.node_composite import CompositeNode, HysteriaProtocol, Hysteria2Protocol, TLSConfig
from .registry import clash_protocol_registry


@clash_protocol_registry.register('hysteria')
def parse_hysteria1(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse Hysteria v1 proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get('name')
        server = proxy.get('server')
        port = proxy.get('port')
        
        if not all([name, server, port]):
            return None
        
        # Create protocol config
        protocol = HysteriaProtocol(
            auth_str=proxy.get('auth-str') or proxy.get('auth_str'),
            obfs=proxy.get('obfs'),
            up_mbps=proxy.get('up'),
            down_mbps=proxy.get('down')
        )
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS configuration
        if proxy.get('tls', True):  # Hysteria typically uses TLS
            node.tls = TLSConfig(
                enabled=True,
                sni=proxy.get('sni') or proxy.get('servername'),
                skip_cert_verify=proxy.get('skip-cert-verify', False),
                fingerprint=proxy.get('fingerprint'),
                alpn=proxy.get('alpn')
            )
        
        return node
        
    except Exception as e:
        print(f"Failed to parse Hysteria v1 proxy: {e}")
        return None


@clash_protocol_registry.register('hysteria2')
def parse_hysteria2(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse Hysteria v2 proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get('name')
        server = proxy.get('server')
        port = proxy.get('port')
        
        if not all([name, server, port]):
            return None
        
        # Create protocol config
        protocol = Hysteria2Protocol(
            password=proxy.get('password'),
            obfs=proxy.get('obfs'),
            obfs_password=proxy.get('obfs-password'),
            up_mbps=proxy.get('up'),
            down_mbps=proxy.get('down')
        )
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS configuration
        if proxy.get('tls', True):  # Hysteria2 typically uses TLS
            node.tls = TLSConfig(
                enabled=True,
                sni=proxy.get('sni') or proxy.get('servername'),
                skip_cert_verify=proxy.get('skip-cert-verify', False),
                fingerprint=proxy.get('fingerprint'),
                alpn=proxy.get('alpn')
            )
        
        return node
        
    except Exception as e:
        print(f"Failed to parse Hysteria v2 proxy: {e}")
        return None