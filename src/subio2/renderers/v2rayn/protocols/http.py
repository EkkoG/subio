"""HTTP proxy renderer for V2rayN format."""
from urllib.parse import quote
from ....models.node_composite import CompositeNode, HttpProtocol
from .registry import v2rayn_protocol_registry


@v2rayn_protocol_registry.register('http')
def render(node: CompositeNode) -> str:
    """Render HTTP proxy node to V2rayN URL format."""
    protocol = node.protocol
    if not isinstance(protocol, HttpProtocol):
        return ""
    
    # Build HTTP URL: http://user:pass@server:port#name
    url = "http://"
    
    # Add authentication if present
    if node.auth:
        url += f"{quote(node.auth.username)}:{quote(node.auth.password)}@"
    
    # Add server and port
    url += f"{node.server}:{node.port}"
    
    # Add name as fragment if present
    if node.name and node.name != f"{node.server}:{node.port}":
        url += f"#{quote(node.name)}"
    
    return url