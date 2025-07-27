"""SOCKS5 renderer for DAE format."""
from urllib.parse import quote
from ....models.node_composite import CompositeNode, Socks5Protocol
from .registry import dae_protocol_registry


@dae_protocol_registry.register('socks5')
def render(node: CompositeNode) -> str:
    """Render SOCKS5 node to DAE URL format."""
    protocol = node.protocol
    if not isinstance(protocol, Socks5Protocol):
        return ""
    
    # Build socks5 URL: socks5://[user:pass@]server:port#name
    url = "socks5://"
    
    # Add authentication if present
    if node.auth:
        url += f"{quote(node.auth.username)}:{quote(node.auth.password)}@"
    
    # Add server and port
    url += f"{node.server}:{node.port}"
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url