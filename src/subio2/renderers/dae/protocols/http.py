"""HTTP renderer for DAE format."""
from urllib.parse import quote
from ....models.node import CompositeNode, HttpProtocol
from .registry import dae_protocol_registry


@dae_protocol_registry.register('http')
def render(node: CompositeNode) -> str:
    """Render HTTP node to DAE URL format."""
    protocol = node.protocol
    if not isinstance(protocol, HttpProtocol):
        return ""
    
    # Build http URL: http://[user:pass@]server:port#name
    url = "http://"
    
    # Add authentication if present
    if node.auth:
        url += f"{quote(node.auth.username)}:{quote(node.auth.password)}@"
    
    # Add server and port
    url += f"{node.server}:{node.port}"
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url