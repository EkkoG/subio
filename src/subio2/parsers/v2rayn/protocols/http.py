"""HTTP proxy URL parser for V2rayN format."""
from typing import Optional
from urllib.parse import urlparse, unquote
from ....models.node import Proxy, HttpProtocol, BasicAuth


def parse(url: str) -> Optional[Proxy]:
    """Parse HTTP proxy URL: http://user:pass@server:port"""
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'http':
            return None
        
        # Extract server and port
        server = parsed.hostname
        port = parsed.port
        if not server or not port:
            return None
        
        # Extract authentication if present
        auth = None
        if parsed.username and parsed.password:
            auth = BasicAuth(
                username=unquote(parsed.username),
                password=unquote(parsed.password)
            )
        
        # Create protocol config
        protocol = HttpProtocol()
        
        # Extract name (default to server:port)
        name = f"{server}:{port}"
        if parsed.fragment:
            name = unquote(parsed.fragment)
        
        # Create node
        return Proxy(
            name=name,
            server=server,
            port=port,
            protocol=protocol,
            auth=auth
        )
        
    except Exception as e:
        print(f"Failed to parse HTTP URL: {e}")
        return None