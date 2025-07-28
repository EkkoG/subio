"""SOCKS5 proxy parser for Surge format."""
from typing import List, Optional
from ....models.node import CompositeNode, Socks5Protocol, BasicAuth
from .registry import surge_protocol_registry


@surge_protocol_registry.register('socks5', 'socks5-tls')
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[CompositeNode]:
    """Parse SOCKS5 proxy from Surge format.
    
    Format: ProxyName = socks5/socks5-tls, server, port, username, password
    """
    try:
        # Extract username and password if present
        username = None
        password = None
        tls = False  # Will be set based on protocol type
        
        if params and len(params) >= 2:
            username = params[0] if params[0] else None
            password = params[1] if params[1] else None
        
        # Create protocol config
        protocol = Socks5Protocol(tls=tls)
        
        # Create auth if credentials provided
        auth = None
        if username and password:
            auth = BasicAuth(username=username, password=password)
        
        # Create node
        return CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol,
            auth=auth
        )
        
    except Exception as e:
        print(f"Failed to parse Surge SOCKS5 proxy: {e}")
        return None