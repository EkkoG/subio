"""SOCKS5 protocol parser for Clash format."""
from typing import Dict, Any, Optional
from ....models.node_composite import CompositeNode, Socks5Protocol, BasicAuth, TLSConfig
from .registry import clash_protocol_registry


@clash_protocol_registry.register('socks5', 'socks')
def parse(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse SOCKS5 proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get('name')
        server = proxy.get('server')
        port = proxy.get('port')
        
        if not all([name, server, port]):
            return None
        
        # Create protocol config
        protocol = Socks5Protocol()
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle authentication
        username = proxy.get('username')
        password = proxy.get('password')
        if username or password:
            node.auth = BasicAuth(username=username, password=password)
        
        # Handle TLS configuration
        if proxy.get('tls'):
            node.tls = TLSConfig(
                enabled=True,
                sni=proxy.get('sni') or proxy.get('servername'),
                skip_cert_verify=proxy.get('skip-cert-verify', False),
                fingerprint=proxy.get('fingerprint')
            )
        
        return node
        
    except Exception as e:
        print(f"Failed to parse SOCKS5 proxy: {e}")
        return None