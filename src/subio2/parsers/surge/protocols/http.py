"""HTTP/HTTPS proxy parser for Surge format."""
from typing import List, Optional
from ....models.node import Proxy, HttpProtocol, BasicAuth, TLSConfig
from .registry import surge_protocol_registry


@surge_protocol_registry.register('http', 'https')
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[Proxy]:
    """Parse HTTP/HTTPS proxy from Surge format.
    
    Format: ProxyName = http/https, server, port, username, password
    """
    try:
        # Extract username and password if present
        username = None
        password = None
        tls = False
        
        if params and len(params) >= 2:
            username = params[0] if params[0] else None
            password = params[1] if params[1] else None
        
        # Check if it's HTTPS (from the original protocol type)
        # Note: We need to check this from the parent context
        # For now, we'll assume HTTP
        
        # Create protocol config
        protocol = HttpProtocol(tls=tls)
        
        # Create auth if credentials provided
        auth = None
        if username and password:
            auth = BasicAuth(username=username, password=password)
        
        # Create node
        return Proxy(
            name=name,
            server=server,
            port=port,
            protocol=protocol,
            auth=auth
        )
        
    except Exception as e:
        print(f"Failed to parse Surge HTTP proxy: {e}")
        return None